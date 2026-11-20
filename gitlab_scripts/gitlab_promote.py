#!/usr/bin/env python3
"""Sequential, approved branch promotion across GitLab projects. Python 3.10+."""

from __future__ import annotations

import argparse
from copy import copy
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import errno
import fnmatch
import getpass
from http.client import HTTPException
import json
import logging
import math
import os
from pathlib import Path
import re
import signal
import shutil
import ssl
import subprocess
import sys
import tempfile
import threading
import time
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, quote, unquote, urlencode, urlsplit
from urllib.request import HTTPRedirectHandler, HTTPSHandler, Request, build_opener

IS_WINDOWS = os.name == "nt"
if IS_WINDOWS:
    import ctypes
    from ctypes import wintypes
    import msvcrt
else:
    import fcntl
    import termios
    import tty


def terminal_supports_ansi(stream) -> bool:
    if not stream.isatty() or os.environ.get("TERM") == "dumb":
        return False
    if not IS_WINDOWS:
        return True
    try:
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.GetConsoleMode.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
        kernel32.SetConsoleMode.argtypes = [wintypes.HANDLE, wintypes.DWORD]
        handle = msvcrt.get_osfhandle(stream.fileno())
        mode = wintypes.DWORD()
        return bool(kernel32.GetConsoleMode(handle, ctypes.byref(mode))
                    and kernel32.SetConsoleMode(handle, mode.value | 0x0004))
    except (OSError, ValueError, AttributeError):
        return False


def default_log_directory() -> Path:
    if IS_WINDOWS:
        return Path(os.environ.get("LOCALAPPDATA") or Path.home() / "AppData" / "Local") / "gitlab-promote"
    return Path.home() / ".local/state/gitlab-promote"


def configure_console():
    """Keep Unicode output usable in Windows consoles and redirected files."""
    if IS_WINDOWS:
        for stream in (sys.stdout, sys.stderr):
            if hasattr(stream, "reconfigure"):
                stream.reconfigure(encoding="utf-8", errors="replace")


@contextmanager
def keyboard_reader():
    """Yield a key reader and restore POSIX terminal settings on every exit."""
    if IS_WINDOWS:
        def read_key():
            # Poll so Python can process Ctrl+C while waiting for input.
            while not msvcrt.kbhit():
                time.sleep(0.02)
            key = msvcrt.getwch()
            if key in {"\x00", "\xe0"}:
                return {"H": "up", "P": "down"}.get(msvcrt.getwch(), "")
            if key == "\x03":
                raise KeyboardInterrupt
            if key == "\x1a":
                raise EOFError("Branch selection was not completed.")
            return "enter" if key in {"\r", "\n"} else ""
        yield read_key
    else:
        fd = sys.stdin.fileno()
        previous = termios.tcgetattr(fd)

        def read_key():
            key = os.read(fd, 1)
            if not key or key == b"\x04":
                raise EOFError("Branch selection was not completed.")
            if key in {b"\r", b"\n"}:
                return "enter"
            if key == b"\x1b" and os.read(fd, 1) in {b"[", b"O"}:
                return {b"A": "up", b"B": "down"}.get(os.read(fd, 1), "")
            return ""
        try:
            tty.setcbreak(fd)
            yield read_key
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, previous)


def terminate_git(process):
    """Stop Git and its SSH/credential helper children after cancellation."""
    if IS_WINDOWS:
        try:
            subprocess.run(["taskkill", "/PID", str(process.pid), "/T", "/F"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                           timeout=10, check=False)
        except (OSError, subprocess.TimeoutExpired):
            LOG.warning("Could not terminate the Git process tree; stopping Git directly.")
        finally:
            if process.poll() is None:
                process.kill()
    else:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass


LOG = logging.getLogger("gitlab-promote")
IGNORED_DIRS = {"node_modules", "vendor", "dist", "build", "__pycache__", "venv"}
SECRETS: set[str] = set()
SETTINGS_PATH = Path(__file__).resolve().with_name("settings.json")
EMPTY_SETTINGS = {"gitlab_url": "", "gitlab_token": "", "webhook_url": ""}
END_TO_END_STAGES = (("dev", "demo"), ("demo", "beta"), ("beta", "main"))
END_TO_END_DELAY = 30
END_TO_END_NOTE = "Recommendation: select at most one UI application or a few backend applications for end-to-end mode."


class OperationError(Exception):
    """An operation error that can be displayed to the user."""


class APIError(OperationError):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status


class DirtyRepositoryError(OperationError):
    def __init__(self, path: Path, changes: list[dict]):
        self.changes = changes
        lines = []
        states = {"M": "modified", "A": "added", "D": "deleted", "R": "renamed",
                  "C": "copied", "U": "conflict", "T": "file type changed"}
        for change in changes:
            code = change["status"]
            name = json.dumps(change["path"], ensure_ascii=False)
            if change.get("original_path"):
                name = json.dumps(change["original_path"], ensure_ascii=False) + " → " + name
            details = "Untracked" if code == "??" else "; ".join(
                f"{area}: {states.get(status, status)}" for area, status in
                (("stage", code[0]), ("working tree", code[1])) if status != " ")
            lines.append(f"  [{code}] {name} — {details}")
        super().__init__(f"{path}: uncommitted or untracked files found; commit or stash them first.\n"
                         + "\n".join(lines))


def redact(text: str) -> str:
    for secret in sorted(SECRETS, key=len, reverse=True):
        text = text.replace(secret, "[REDACTED]")
    for key in ("GITLAB_TOKEN", "GITLAB_APPROVAL_TOKEN", "GOOGLE_CHAT_WEBHOOK_URL"):
        if os.environ.get(key):
            text = text.replace(os.environ[key], "[REDACTED]")
    text = re.sub(r"(https?://)[^\s/@]+(?::[^\s/@]*)?@", r"\1[REDACTED]@", text)
    text = re.sub(r"glpat-[A-Za-z0-9_.-]+", "[REDACTED]", text)
    return text


def plain_text(text: str) -> str:
    text = re.sub(r"\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)", "", text)
    text = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", text)
    return re.sub(r"[\x00-\x08\x0b-\x1f\x7f]", "", text)


class RedactingFormatter(logging.Formatter):
    def format(self, record):
        return plain_text(redact(super().format(record)))


class ConsoleFormatter(RedactingFormatter):
    COLORS = {"error": "31", "success": "32", "warning": "33", "link": "36;4", "section": "1;36", "info": "36"}

    def __init__(self, color: bool):
        super().__init__("%(message)s")
        self.color = color

    def format(self, record):
        message = super().format(record)
        kind = "error" if record.levelno >= logging.ERROR else "warning" if record.levelno >= logging.WARNING else getattr(record, "kind", "info")
        label = {"error": "ERROR", "success": "OK", "warning": "WARN", "link": "MR", "section": "STEP", "info": "INFO"}[kind]
        time_label = self.formatTime(record, "%H:%M:%S")
        if kind == "section":
            line = "\n" + "─" * 64 + f"\n{time_label}  {message}\n" + "─" * 64
        else:
            line = f"{time_label}  {label:<6}  {message}"
        return f"\033[{self.COLORS[kind]}m{line}\033[0m" if self.color else line


class ConsoleHandler(logging.StreamHandler):
    def __init__(self, stream=None, color="auto", animate=True):
        super().__init__(stream)
        terminal = terminal_supports_ansi(self.stream)
        use_color = color == "always" or (color == "auto" and terminal and "NO_COLOR" not in os.environ)
        self.animate = animate and terminal
        self.live = False
        self.setFormatter(ConsoleFormatter(use_color))

    def clear_live(self):
        if self.live:
            self.stream.write("\r\033[2K")
            self.stream.flush()
            self.live = False

    def emit(self, record):
        with self.lock:
            self.clear_live()
            super().emit(record)


@contextmanager
def activity(label: str, duration: float | None = None):
    console = next((h for h in LOG.handlers if isinstance(h, ConsoleHandler) and h.animate), None)
    if console is None:
        yield
        return
    stop = threading.Event()
    started = time.monotonic()

    def draw():
        frame = 0
        while not stop.is_set():
            elapsed = time.monotonic() - started
            if duration is not None and duration > 0:
                fraction = min(elapsed / duration, 1)
                filled = int(16 * fraction)
                indicator = "[" + "█" * filled + "░" * (16 - filled) + f"] {max(0, duration - elapsed):.0f} s"
            else:
                indicator = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"[frame % 10] + f" {elapsed:.0f} s"
            width = max(20, shutil.get_terminal_size((80, 24)).columns - 1)
            line = plain_text(redact(f"  {indicator}  {label}"))[:width]
            with console.lock:
                console.stream.write("\r\033[2K" + line)
                console.stream.flush()
                console.live = True
            frame += 1
            stop.wait(0.1)

    worker = threading.Thread(target=draw, daemon=True)
    worker.start()
    try:
        yield
    finally:
        stop.set()
        worker.join()
        with console.lock:
            console.clear_live()


def section(message: str, *args):
    LOG.info(message, *args, extra={"kind": "section"})


def success(message: str, *args):
    LOG.info(message, *args, extra={"kind": "success"})


def mr_link(project):
    if project.mr_url:
        LOG.info("[%s] %s", project.label, project.mr_url, extra={"kind": "link"})


def setup_logging(directory: Path, color="auto", animate=True) -> tuple[Path, Path]:
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
    log_path = directory / f"run-{stamp}-{os.getpid()}.log"
    fd = os.open(log_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    file_handler = logging.StreamHandler(os.fdopen(fd, "w", encoding="utf-8"))
    console = ConsoleHandler(color=color, animate=animate)
    formatter = RedactingFormatter("%(asctime)s %(levelname)-7s %(message)s")
    LOG.setLevel(logging.DEBUG)
    file_handler.setLevel(logging.DEBUG)
    console.setLevel(logging.INFO)
    for old in LOG.handlers[:]:
        old.close()
        LOG.removeHandler(old)
    file_handler.setFormatter(formatter)
    for handler in (file_handler, console):
        LOG.addHandler(handler)
    LOG.propagate = False
    return log_path, log_path.with_suffix(".json")


@contextmanager
def run_lock():
    # One process per user, including different but overlapping --root directories.
    if IS_WINDOWS:
        directory = default_log_directory()
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / "run.lock"
    else:
        path = Path(tempfile.gettempdir()) / f"gitlab-promote-{os.getuid()}.lock"
    fd = os.open(path, os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        try:
            if IS_WINDOWS:
                msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
            else:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            if exc.errno not in {errno.EACCES, errno.EAGAIN, errno.EDEADLK}:
                raise
            raise OperationError("Another gitlab-promote process is running.") from exc
        yield
    finally:
        os.close(fd)


def git(path: Path, *args: str, timeout: float = 120, check: bool = True):
    env = os.environ.copy()
    # Prevent inherited Git directory/index variables from redirecting to another repository.
    for key in ("GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_COMMON_DIR"):
        env.pop(key, None)
    env.update(GIT_TERMINAL_PROMPT="0", GIT_OPTIONAL_LOCKS="0")
    env.setdefault("GIT_SSH_COMMAND", "ssh -o BatchMode=yes -o ConnectTimeout=20")
    command = ["git", "-C", str(path), *args]
    LOG.debug("[%s] git %s", path, " ".join(args))
    try:
        with activity(f"{path}: git {' '.join(args)}"), subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              text=True, encoding="utf-8", errors="replace", env=env,
                              start_new_session=not IS_WINDOWS,
                              creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if IS_WINDOWS else 0) as process:
            try:
                stdout, stderr = process.communicate(timeout=timeout)
            except (subprocess.TimeoutExpired, KeyboardInterrupt):
                terminate_git(process)
                process.communicate()
                raise
            result = subprocess.CompletedProcess(command, process.returncode, stdout, stderr)
    except (subprocess.TimeoutExpired, OSError) as exc:
        raise OperationError(f"{path}: Git command failed or timed out: {' '.join(args)}") from exc
    if check and result.returncode:
        raise OperationError(f"{path}: git {' '.join(args)}: {redact(result.stderr.strip() or result.stdout.strip())}")
    return result


def discover(root: Path, includes: list[str], excludes: list[str]) -> list[Path]:
    found = []

    def fail(error):
        raise OperationError(f"Could not read directory: {error}")

    for current, dirs, files in os.walk(root, followlinks=False, onerror=fail):
        path = Path(current)
        relative = path.relative_to(root).as_posix()
        if any(fnmatch.fnmatch(relative, p) or fnmatch.fnmatch(path.name, p) for p in excludes):
            dirs[:] = []
            continue
        dirs[:] = sorted(d for d in dirs if not d.startswith(".") and d not in IGNORED_DIRS
                         and not (path / d).is_symlink())
        if path != root and (path / ".git").exists():
            dirs[:] = []  # Submodules inside a repository are not processed as separate projects.
            if not includes or any(fnmatch.fnmatch(relative, p) or fnmatch.fnmatch(path.name, p)
                                   for p in includes):
                found.append(path)
    # Keep shorturl last in the project list and subsequent workflow.
    return sorted(found, key=lambda path: (
        path.relative_to(root).as_posix() == "microservices/shorturl", path))


def project_from_remote(remote: str, base_url: str, ssh_host: str | None = None) -> str:
    base = urlsplit(base_url)
    if "://" in remote:
        parsed = urlsplit(remote)
        if parsed.scheme not in {"ssh", "http", "https"}:
            raise OperationError("Only SSH/HTTPS GitLab remote URLs are supported.")
        host, path = parsed.hostname, unquote(parsed.path).lstrip("/")
        web_remote = parsed.scheme in {"http", "https"}
        if web_remote and (parsed.scheme, parsed.netloc.rsplit("@", 1)[-1]) != (base.scheme, base.netloc):
            raise OperationError("The HTTP remote URL does not match the --gitlab-url server.")
    else:
        matched = re.fullmatch(r"(?:[^@/:]+@)?([^/:]+):(.+)", remote)
        if not matched:
            raise OperationError("The remote is not a GitLab SSH/HTTPS URL.")
        host, path = matched.groups()
        web_remote = False
    if host not in {base.hostname, ssh_host}:
        raise OperationError(f"Remote host ({host}) does not match the GitLab server; use --ssh-host for an SSH alias.")
    prefix = base.path.strip("/")
    if web_remote and prefix:
        if not path.startswith(prefix + "/"):
            raise OperationError("The remote URL does not match the GitLab subdirectory.")
        path = path[len(prefix) + 1:]
    path = path.removesuffix(".git").strip("/")
    if len(path.split("/")) < 2 or any(p in {"", ".", ".."} for p in path.split("/")):
        raise OperationError("Could not extract the GitLab group/project path from the remote URL.")
    return path


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        # Do not forward PRIVATE-TOKEN on redirects to another server.
        return None


def validate_webhook(value: str) -> str:
    value = value.strip()
    # Mask the full URL and query secrets in errors and log messages.
    if value:
        SECRETS.add(value)
    try:
        parsed = urlsplit(value)
        query = parse_qs(parsed.query)
        valid = (parsed.scheme == "https" and parsed.hostname == "chat.googleapis.com"
                 and parsed.port in {None, 443} and not parsed.username and not parsed.password
                 and not parsed.fragment and not re.search(r"\s|[\\\x00-\x1f\x7f]", value)
                 and re.fullmatch(r"/v1/spaces/[A-Za-z0-9_-]+/messages", parsed.path)
                 and len(query.get("key", [])) == 1 and len(query.get("token", [])) == 1)
    except ValueError:
        valid = False
    if not valid:
        raise OperationError("An HTTPS incoming webhook URL copied from Google Chat is required (including key and token).")
    SECRETS.update(query["key"] + query["token"])
    return value


class ChatNotifier:
    def __init__(self, url: str, timeout: float = 10, dry_run: bool = False):
        self.url = validate_webhook(url)
        self.timeout, self.dry_run = timeout, dry_run
        self.opener = build_opener(NoRedirect(), HTTPSHandler(context=ssl.create_default_context()))
        self.sent = 0
        self.failed = 0
        self.events: set[tuple] = set()
        self.last_attempt: float | None = None

    def error(self, args, stage: str, detail: str, project=None):
        key = (project.path if project else "", stage, detail)
        if key in self.events:
            return
        self.events.add(key)
        if self.dry_run:
            LOG.info("Dry run: Google Chat error notification was not sent.")
            return
        account = getattr(args, "account", None) or {}
        parts = ["GitLab batch promotion error", f"Operation: {args.source} → {args.target}",
                 f"Stage: {stage}", f"Project: {project.label if project else 'Overall operation'}"]
        if project and project.name:
            parts.append(f"GitLab project: {project.name} (ID: {project.project_id})")
        if account.get("username"):
            parts.append(f"Account: @{account['username']}")
        parts.append("Error: " + plain_text(redact(detail))[:6000])
        parts.append(f"MR: {project.mr_url if project and project.mr_url else 'Not created yet/unknown'}")
        self._send("\n".join(parts), project.label if project else stage)

    def send_test(self, args) -> bool:
        # Call only with separate, explicit user approval; may also send during a dry run.
        message = ("gitlab-promote — Google Chat test message\n"
                   f"Selected operation: {args.source} → {args.target}\n"
                   "This message was sent to test the webhook connection; it is not an error notification.")
        return self._send(message, "Webhook connection test", is_test=True)

    def _send(self, message: str, context: str, is_test: bool = False) -> bool:
        message = plain_text(redact(message)).replace("<", "‹").replace(">", "›")
        kind = "test message" if is_test else "error notification"
        request = Request(self.url, data=json.dumps({"text": message}).encode(), method="POST",
                          headers={"Content-Type": "application/json; charset=UTF-8"})
        try:
            if self.last_attempt is not None:
                wait = max(0, 1 - (time.monotonic() - self.last_attempt))
                if wait:
                    time.sleep(wait)
            self.last_attempt = time.monotonic()
            # Do not retry writes: avoid duplicate notifications if the response is lost.
            with activity(f"Sending Google Chat {kind}"), self.opener.open(request, timeout=self.timeout) as response:
                response.read()
            self.sent += 1
            success("Google Chat %s sent: %s", kind, context)
            return True
        except (HTTPError, URLError, OSError, HTTPException, ValueError):
            self.failed += 1
            # The response body or exception may contain URL secrets; do not log them.
            LOG.log(logging.ERROR if is_test else logging.WARNING,
                    "Could not send Google Chat %s; check the URL, access, and network. The main workflow will continue.", kind)
            return False


def configure_chat(args):
    if getattr(args, "no_chat", False):
        LOG.info("Google Chat error notifications are disabled.")
        return None
    if hasattr(args, "settings"):
        value = args.settings["webhook_url"]
        if not value:
            return None
        notifier = ChatNotifier(value, getattr(args, "chat_timeout", 10), args.dry_run)
        LOG.info("Google Chat error notifications: %s.", "disabled during dry run" if args.dry_run else "enabled")
        if getattr(args, "webhook_changed", False) and sys.stdin.isatty() and not args.yes and ask_yes_no(
                "Send a real test message to Google Chat?"):
            notifier.send_test(args)
        return notifier
    value = os.environ.get("GOOGLE_CHAT_WEBHOOK_URL", "").strip()
    original_webhook = value
    interactive = sys.stdin.isatty() and not args.yes
    if value:
        SECRETS.add(value)
        LOG.info("Google Chat webhook: configured (hidden).")
        if interactive and not ask_yes_no("Keep the current Google Chat webhook?"):
            value = getpass.getpass("Google Chat webhook URL (optional, hidden; Enter: disable): ").strip()
    elif interactive:
        value = getpass.getpass("Google Chat webhook URL (optional, hidden; Enter: skip): ").strip()
    while value:
        try:
            notifier = ChatNotifier(value, getattr(args, "chat_timeout", 10), args.dry_run)
            LOG.info("Google Chat error notifications: %s.", "disabled during dry run" if args.dry_run else "enabled")
            prompt = "Send a test message to Google Chat?"
            if args.dry_run:
                prompt = "You are in dry-run mode. Send a real test message to Google Chat?"
            if value != original_webhook and interactive and ask_yes_no(prompt):
                notifier.send_test(args)
            return notifier
        except OperationError as exc:
            if not interactive:
                raise
            LOG.warning("%s", exc)
            value = getpass.getpass("Google Chat webhook URL (hidden; Enter: skip): ").strip()
    LOG.info("Google Chat error notifications are disabled.")
    return None


def notify_error(args, stage: str, detail: str, project=None):
    notifier = getattr(args, "chat", None)
    if notifier:
        notifier.error(args, stage, detail, project)


def record_project_error(project, status: str, exc: Exception):
    project.status, project.detail = status, str(exc)
    if isinstance(exc, DirtyRepositoryError):
        project.local_changes = exc.changes


class GitLab:
    def __init__(self, base_url: str, token: str, timeout: float = 30, retries: int = 3,
                 ca_file: str | None = None):
        self.url = base_url.rstrip("/") + "/api/v4"
        self.token, self.timeout, self.retries = token, timeout, retries
        context = ssl.create_default_context(cafile=ca_file)
        self.opener = build_opener(NoRedirect(), HTTPSHandler(context=context))

    def request(self, method: str, path: str, data=None, query=None):
        url = self.url + path + ("?" + urlencode(query) if query else "")
        payload = json.dumps(data).encode() if data is not None else None
        for attempt in range(self.retries + 1):
            request = Request(url, data=payload, method=method,
                              headers={"PRIVATE-TOKEN": self.token, "Content-Type": "application/json",
                                       "Accept": "application/json", "User-Agent": "gitlab-promote/1.0"})
            try:
                with activity(f"Waiting for GitLab response: {method} {path}"), self.opener.open(request, timeout=self.timeout) as response:
                    body = response.read()
                    return json.loads(body) if body else {}
            except HTTPError as exc:
                message = exc.read().decode("utf-8", errors="replace").replace(self.token, "[REDACTED]")
                if method == "GET" and (exc.code == 429 or exc.code in {500, 502, 503, 504}) and attempt < self.retries:
                    retry_after = exc.headers.get("Retry-After", "")
                    delay = min(float(retry_after), 60) if retry_after.isdigit() else min(2 ** attempt, 10)
                    LOG.warning("API HTTP %s; retrying the read request in %.1f seconds.", exc.code, delay)
                    time.sleep(delay)
                    continue
                raise APIError(exc.code, f"GitLab {method} {path}: HTTP {exc.code}: {redact(message[:1000])}") from exc
            except (URLError, TimeoutError, OSError, HTTPException) as exc:
                if method == "GET" and attempt < self.retries:
                    LOG.warning("API connection error; the read request will be retried.")
                    time.sleep(min(2 ** attempt, 10))
                    continue
                raise APIError(0, f"GitLab {method} {path}: connection error or timeout. "
                               "If a write request was sent, check the result on the server.") from exc
            except (ValueError, UnicodeError) as exc:
                raise APIError(0, f"GitLab {method} {path}: invalid JSON response.") from exc

    def all(self, path: str, query=None) -> list:
        result = []
        page = 1
        while True:
            batch = self.request("GET", path, query={**(query or {}), "per_page": 100, "page": page})
            if not isinstance(batch, list):
                raise OperationError("The GitLab list response has an unexpected format.")
            result.extend(batch)
            if len(batch) < 100:
                return result
            page += 1


def ask_yes_no(prompt: str) -> bool:
    while True:
        answer = input(prompt + " [Enter: yes / n: no]: ").strip().lower()
        if answer in {"", "y", "yes"}:
            return True
        if answer in {"n", "no"}:
            return False
        print("Press Enter for yes or type n for no.", flush=True)


def validate_branches(source: str, target: str):
    if source == target:
        raise OperationError("Source and target branches must be different.")
    for branch in (source, target):
        # Accept only actual ref names; reject shorthand such as HEAD and @{-1}.
        if (not branch or branch == "HEAD" or branch.startswith("-")
                or subprocess.run(["git", "check-ref-format", "refs/heads/" + branch],
                                  capture_output=True).returncode):
            raise OperationError(f"Invalid branch name: {branch}")


def select_workflow(args):
    if args.workflow is None:
        if args.source is not None or args.yes or not sys.stdin.isatty():
            args.workflow = "traditional"
        else:
            print("\nSelect workflow mode:")
            print("  1. Traditional mode")
            print("  2. End-to-end mode (dev -> demo -> beta -> main)")
            while True:
                choice = input("Choice [1-2, Enter: 1]: ").strip() or "1"
                if choice in {"1", "2"}:
                    args.workflow = "traditional" if choice == "1" else "end-to-end"
                    break
                print("Enter 1 or 2.")
    if args.workflow == "end-to-end":
        if args.source is not None or args.target is not None:
            raise OperationError("End-to-end mode uses a route; omit --source and --target.")
        if args.mode != "merge":
            raise OperationError("End-to-end mode requires --mode merge.")
        args.end_to_end_stages = select_end_to_end_route(args)
        args.source, args.target = args.end_to_end_stages[0]
        LOG.info("%s", END_TO_END_NOTE)
    else:
        select_branches(args)


def select_menu(title: str, labels: list[str]) -> int:
    selected = 0
    ansi = terminal_supports_ansi(sys.stdout)

    def draw():
        for index, label in enumerate(labels):
            sys.stdout.write("\033[2K" + ("  > " if index == selected else "    ") + label + "\n")
        sys.stdout.flush()

    if ansi:
        print(f"\n{title} (↑/↓: select, Enter: continue, Ctrl+C: cancel):")
        with keyboard_reader() as read_key:
            draw()
            while True:
                key = read_key()
                if key == "enter":
                    break
                if key in {"up", "down"}:
                    selected = (selected + (-1 if key == "up" else 1)) % len(labels)
                    sys.stdout.write(f"\033[{len(labels)}A")
                    draw()
    else:
        print(f"\n{title}:")
        for index, label in enumerate(labels, 1):
            print(f"  {index}. {label}")
        while True:
            choice = input(f"Choice [1-{len(labels)}, Enter: 1]: ").strip() or "1"
            if choice.isascii() and choice.isdigit() and 1 <= int(choice) <= len(labels):
                selected = int(choice) - 1
                break
            print(f"Enter a number between 1 and {len(labels)}.")
    return selected


def select_end_to_end_route(args):
    if args.yes or not sys.stdin.isatty():
        return END_TO_END_STAGES
    selected = select_menu("Select end-to-end namespace route", ["dev demo beta main", "custom"])
    if selected == 0:
        stages = END_TO_END_STAGES
    else:
        while True:
            branches = input("Namespaces (branches) in promotion order (e.g. dev demo beta): ").split()
            if len(branches) < 2:
                print("Enter at least two namespaces separated by spaces.")
                continue
            stages = tuple(zip(branches, branches[1:]))
            try:
                for source, target in stages:
                    validate_branches(source, target)
            except OperationError as exc:
                print(str(exc))
                continue
            break
    success("Selected route: %s", " -> ".join([stages[0][0]] + [target for _, target in stages]))
    return stages


def select_branches(args):
    if args.source and args.target:
        return
    if not sys.stdin.isatty():
        raise OperationError("Run in an interactive terminal to select branches; use --source and --target for automation.")
    options = [("dev", "demo"), ("demo", "beta"), ("beta", "main"), ("dev", "main")]
    labels = [f"{source} -> {target}" for source, target in options] + ["custom"]
    selected = select_menu("Select branch promotion", labels)
    if selected < len(options):
        args.source, args.target = options[selected]
    else:
        while True:
            branches = input("Source and target branches (e.g. dev beta): ").split()
            if len(branches) != 2:
                print("Enter two branches separated by a space (e.g. dev beta).")
                continue
            try:
                validate_branches(*branches)
            except OperationError as exc:
                print(str(exc))
                continue
            args.source, args.target = branches
            break
    success("Selected promotion: %s → %s", args.source, args.target)


def validate_url(value: str) -> str:
    value = value.strip()
    if value and "://" not in value:
        value = "https://" + value
    try:
        url = urlsplit(value)
        valid = (url.scheme == "https" and url.hostname and not url.username and not url.password
                 and not url.query and not url.fragment and not re.search(r"\s|[\\\x00-\x1f\x7f]", value))
        url.port  # Reject invalid ports before sending a token.
    except ValueError:
        valid = False
    if not valid:
        raise OperationError("Enter a valid GitLab server URL (e.g. gitlab.com or https://gitlab.yourcompany.com).")
    return value.rstrip("/")


def prompt_url(current: str = "") -> str:
    while True:
        suffix = f" [{current}]" if current else " (e.g. gitlab.com)"
        value = input(f"GitLab URL{suffix}: ").strip() or current
        try:
            address = validate_url(value)
            LOG.info("GitLab URL: %s", address)
            return address
        except OperationError as exc:
            LOG.warning("%s", exc)


def prompt_token(label: str) -> str:
    while True:
        token = getpass.getpass(f"{label} access token (api scope, hidden input): ").strip()
        if token:
            SECRETS.add(token)
            return token
        LOG.warning("A token is required; it cannot be empty.")


def save_settings(values: dict, path: Path = SETTINGS_PATH):
    temporary = None
    try:
        fd, temporary = tempfile.mkstemp(prefix=".settings-", suffix=".json", dir=path.parent)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(values, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
        os.replace(temporary, path)
    finally:
        if temporary and os.path.exists(temporary):
            os.unlink(temporary)


def configure_settings(args, path: Path = SETTINGS_PATH):
    if not path.exists():
        save_settings(EMPTY_SETTINGS, path)
    try:
        contents = path.read_text(encoding="utf-8-sig").strip()
        stored = json.loads(contents) if contents else {}
    except (ValueError, UnicodeError) as exc:
        raise OperationError(f"{path}: a valid JSON settings file is required.") from exc
    if not isinstance(stored, dict) or any(
            not isinstance(stored.get(key, ""), str) for key in EMPTY_SETTINGS):
        raise OperationError(f"{path}: settings must be a JSON object with string values.")
    values = {key: stored.get(key, "").strip() for key in EMPTY_SETTINGS}
    original_webhook = values["webhook_url"]
    values["gitlab_url"] = args.gitlab_url or values["gitlab_url"]
    environment_token = os.environ.get("GITLAB_TOKEN", "").strip()
    if getattr(args, "token_source", "settings") == "environment":
        if not environment_token:
            raise OperationError("--token-source environment requires GITLAB_TOKEN.")
        values["gitlab_token"] = environment_token
        token_source = "GITLAB_TOKEN"
    elif values["gitlab_token"]:
        token_source = str(path)
        if environment_token and environment_token != values["gitlab_token"]:
            LOG.warning("GITLAB_TOKEN differs from settings.json; using settings.json. "
                        "Use --token-source environment to select GITLAB_TOKEN explicitly.")
    else:
        values["gitlab_token"] = environment_token
        token_source = "GITLAB_TOKEN" if environment_token else "terminal input"
    values["webhook_url"] = os.environ.get("GOOGLE_CHAT_WEBHOOK_URL", "").strip() or values["webhook_url"]
    for key in ("gitlab_token", "webhook_url"):
        if values[key]:
            SECRETS.add(values[key])
    interactive = sys.stdin.isatty() and not args.yes
    if any(values.values()):
        print("\nCurrent settings:")
        print("  GitLab URL: " + plain_text(values["gitlab_url"] or "empty"))
        print("  Token: " + ("configured (hidden)" if values["gitlab_token"] else "empty"))
        print("  Token source: " + plain_text(token_source))
        webhook = values["webhook_url"]
        print("  Webhook URL: " + (plain_text(webhook.split("?", 1)[0]) + "?********" if webhook else "empty"))
        change = interactive and not ask_yes_no("Keep the current settings? (n: edit all three in order)")
    else:
        change = False
    for key in EMPTY_SETTINGS:
        if key == "webhook_url" and args.no_chat:
            continue
        while True:
            if change or not values[key]:
                if not interactive:
                    raise OperationError(f"{path}: {key} is missing; run in a terminal or complete the settings file.")
                if key == "gitlab_url":
                    values[key] = prompt_url(values[key])
                elif key == "gitlab_token":
                    values[key] = prompt_token("GitLab account")
                else:
                    values[key] = getpass.getpass("Google Chat webhook URL (hidden): ").strip()
            try:
                if key == "gitlab_url":
                    values[key] = validate_url(values[key])
                elif key == "webhook_url":
                    values[key] = validate_webhook(values[key])
                break
            except OperationError as exc:
                if not interactive:
                    raise
                LOG.warning("%s", exc)
                values[key] = ""
    # Persist credentials only after GitLab has accepted them in connect_account.
    args.webhook_changed = values["webhook_url"] != original_webhook
    args.settings = values
    args.settings_path = path
    args.gitlab_url = values["gitlab_url"]


def account_identity(api):
    user = api.request("GET", "/user")
    if not isinstance(user, dict) or not user.get("username") or not user.get("id"):
        raise OperationError("Could not verify the GitLab account; the user response is incomplete.")
    return {key: user[key] for key in ("id", "username", "name", "web_url") if key in user}


def connect_account(args, token_env: str, label: str, allow_url_change: bool):
    interactive = sys.stdin.isatty() and not args.yes
    token = os.environ.get(token_env, "").strip()
    if token_env == "GITLAB_TOKEN" and hasattr(args, "settings"):
        token = args.settings["gitlab_token"]
    if token:
        SECRETS.add(token)
    LOG.info("%s | Server: %s | Token: %s", label, args.gitlab_url or "not configured",
             "configured (hidden)" if token else "not configured")
    if not args.gitlab_url:
        if not interactive:
            raise OperationError("A GitLab URL is required: set --gitlab-url or GITLAB_URL.")
        args.gitlab_url = prompt_url()
    if not token:
        if not interactive:
            raise OperationError(f"{token_env} is required; it will be requested as hidden input in an interactive terminal.")
        token = prompt_token(label)
    while True:
        api = GitLab(args.gitlab_url, token, args.api_timeout, ca_file=args.ca_file)
        try:
            user = account_identity(api)
        except APIError as exc:
            if exc.status not in {401, 403}:
                raise
            LOG.error("GitLab rejected the selected credentials (HTTP %s). Check the token's "
                      "server, expiry/revocation and permissions. Settings file: %s. "
                      "GITLAB_APPROVAL_TOKEN is separate when --approve is used.",
                      exc.status, getattr(args, "settings_path", SETTINGS_PATH))
            if not interactive:
                raise
            LOG.error("Could not verify %s: %s", label, exc)
            if not ask_yes_no("Would you like to change the GitLab credentials?"):
                raise OperationError("Cannot continue without a valid GitLab account.") from exc
        else:
            identity = {key: user[key] for key in ("id", "username", "name", "web_url") if key in user}
            success("%s verified | %s (@%s) | ID: %s | %s", label,
                    user.get("name", ""), user["username"], user["id"], args.gitlab_url)
            if not interactive or (token_env == "GITLAB_TOKEN" and hasattr(args, "settings")) or ask_yes_no(f"Keep the current {label} details?"):
                os.environ[token_env] = token
                if token_env == "GITLAB_TOKEN" and hasattr(args, "settings"):
                    args.settings.update(gitlab_url=args.gitlab_url, gitlab_token=token)
                    save_settings(args.settings, args.settings_path)
                return api, identity
        if allow_url_change:
            args.gitlab_url = prompt_url(args.gitlab_url)
        # Prevent sending the old token to a new server when the server changes.
        token = prompt_token(label)


def configure_accounts(args):
    section("1/5 — GitLab account details | %s → %s", args.source, args.target)
    api, args.account = connect_account(args, "GITLAB_TOKEN", "GitLab account", True)
    approver = None
    args.approval_account = None
    if args.approve:
        if os.environ.get("GITLAB_APPROVAL_TOKEN", "").strip():
            approver, args.approval_account = connect_account(args, "GITLAB_APPROVAL_TOKEN", "Approval account", False)
        else:
            approver, args.approval_account = api, args.account
            LOG.info("If required, MR approval will use the same account: @%s", args.account["username"])
    return api, approver


@dataclass
class Project:
    path: str
    name: str = ""
    project_id: int = 0
    current_branch: str = ""
    source_sha: str = ""
    target_sha: str = ""
    commits: int = 0
    status: str = "discovered"
    detail: str = ""
    mr_url: str = ""
    mr_iid: int = 0
    selected: bool = True
    relative_path: str = ""
    local_changes: list[dict] = field(default_factory=list)
    prepared_sha: str = ""

    @property
    def label(self) -> str:
        return self.relative_path or self.name or self.path


STATUS_LABELS = {
    "discovered": "Discovered", "not_selected": "Not selected", "planned": "Planned",
    "no_changes": "No commits to promote", "preflight_error": "Preflight error",
    "prepared": "Git preparation completed", "git_error": "Git error",
    "processing": "Processing", "mr_open": "MR open", "merged": "Merge completed",
    "mr_created": "MR ready", "conflict": "Conflict", "blocked": "Blocked by GitLab",
    "timeout": "Timeout", "merge_unconfirmed": "Merge unconfirmed", "mr_error": "MR error",
}


def parse_selection(value: str, total: int) -> list[int]:
    value = value.strip().lower()
    if value in {"", "all"}:
        return list(range(total))
    if value in {"n", "cancel", "q", "no"}:
        return []
    chosen = set()
    for part in re.split(r"[,\s]+", value):
        match = re.fullmatch(r"([0-9]+)(?:-([0-9]+))?", part)
        if not match:
            raise OperationError("Invalid selection. Example: 1,3,5-7 or all.")
        start, end = int(match[1]), int(match[2] or match[1])
        if not 1 <= start <= end <= total:
            raise OperationError(f"Project numbers must be between 1 and {total}.")
        chosen.update(range(start - 1, end))
    return sorted(chosen)


def select_projects(projects: list[Project], args) -> list[Project]:
    section("Discovered projects (%s)", len(projects))
    for index, project in enumerate(projects, 1):
        print(f"  {index:>2}. Project found: {project.label}", flush=True)
        project.selected = False
        project.status = "not_selected"
    if args.yes or (args.dry_run and not sys.stdin.isatty()):
        indices = list(range(len(projects)))
        LOG.info("All projects matching the filters were selected.")
    elif not sys.stdin.isatty():
        raise OperationError("Project selection requires an interactive terminal; use --include/--exclude and --yes for automation.")
    else:
        while True:
            answer = input("\nWhich projects? (Enter: all / n: cancel / e.g. 1,3,5-7): ")
            try:
                indices = parse_selection(answer, len(projects))
                break
            except OperationError as exc:
                LOG.warning("%s", exc)
    selected = [projects[index] for index in indices]
    for project in selected:
        project.selected, project.status = True, "discovered"
    LOG.info("%s/%s projects selected.", len(selected), len(projects))
    return selected


def progress(stage: str, done: int, total: int, detail: str, status: str = ""):
    percent = 100 * done / total if total else 100
    width = 20
    filled = max(0, min(width, int(width * percent / 100)))
    bar = "[" + "█" * filled + "░" * (width - filled) + "]"
    kind = "success" if status in {"merged", "mr_created", "no_changes", "prepared"} else "info"
    level = logging.ERROR if status in {"preflight_error", "git_error", "mr_error", "conflict", "blocked", "timeout", "merge_unconfirmed"} else logging.INFO
    LOG.log(level, "%s | %s/%s (%d%%) | %s | %s", stage, done, total, percent, bar, detail, extra={"kind": kind})


def show_summary(projects: list[Project], outcome: str):
    counts: dict[str, int] = {}
    for project in projects:
        counts[project.status] = counts.get(project.status, 0) + 1
    outcome_label = {"completed": "Operation completed", "partial_failure": "Some projects could not be completed",
                     "aborted": "Operation stopped due to an error", "cancelled": "Cancelled by user",
                     "interrupted": "Operation interrupted", "dry_run": "Dry run completed"}.get(outcome, outcome)
    section("RESULT — %s | Selected: %s/%s", outcome_label, sum(p.selected for p in projects), len(projects))
    for project in projects:
        failed = project.status in {"preflight_error", "git_error", "mr_error", "conflict", "blocked", "timeout", "merge_unconfirmed"}
        completed = project.status in {"merged", "mr_created", "no_changes"}
        LOG.log(logging.ERROR if failed else logging.INFO, "%-25s | %s", project.label,
                STATUS_LABELS.get(project.status, project.status), extra={"kind": "success" if completed else "info"})
        if project.detail:
            LOG.log(logging.ERROR if failed else logging.INFO, "  Details: %s", project.detail,
                    extra={"kind": "success" if completed else "info"})
        mr_link(project)
    for status, count in counts.items():
        LOG.info("  %s: %s", STATUS_LABELS.get(status, status), count)
    if outcome in {"completed", "dry_run"}:
        success("%s.", outcome_label)
    elif outcome in {"partial_failure", "aborted", "interrupted"}:
        LOG.error("%s. Review the project results above.", outcome_label)


def local_changes(path: Path, timeout: float) -> list[dict]:
    output = git(path, "status", "--porcelain=v1", "-z", "--untracked-files=all", timeout=timeout).stdout
    records = iter(output.split("\0"))
    changes = []
    for record in records:
        if not record:
            continue
        if len(record) < 4 or record[2] != " ":
            raise OperationError(f"{path}: Could not parse Git status output.")
        change = {"status": record[:2], "path": record[3:]}
        if "R" in record[:2] or "C" in record[:2]:
            original = next(records, "")
            if not original:
                raise OperationError(f"{path}: Could not read the original name of the renamed file.")
            change["original_path"] = original
        changes.append(change)
    return changes


def clean_repository(path: Path, timeout: float):
    top = git(path, "rev-parse", "--show-toplevel", timeout=timeout).stdout.strip()
    if Path(top).resolve() != path.resolve():
        raise OperationError(f"{path}: not a standalone Git working tree.")
    changes = local_changes(path, timeout)
    if changes:
        raise DirtyRepositoryError(path, changes)
    for marker in ("MERGE_HEAD", "CHERRY_PICK_HEAD", "REVERT_HEAD", "rebase-merge", "rebase-apply", "sequencer", "BISECT_START"):
        marker_path = Path(git(path, "rev-parse", "--git-path", marker, timeout=timeout).stdout.strip())
        if not marker_path.is_absolute():
            marker_path = path / marker_path
        if marker_path.exists():
            raise OperationError(f"{path}: a Git operation is in progress ({marker}).")


def inspect_project(project: Project, api: GitLab, args):
    path = Path(project.path)
    clean_repository(path, args.git_timeout)
    project.current_branch = git(path, "symbolic-ref", "--quiet", "--short", "HEAD", check=False).stdout.strip() or "(detached HEAD)"
    remote = git(path, "remote", "get-url", args.remote).stdout.strip()
    project.name = project_from_remote(remote, args.gitlab_url, args.ssh_host)
    info = api.request("GET", "/projects/" + quote(project.name, safe=""))
    if info.get("archived"):
        raise OperationError("The project is archived.")
    project.project_id = info["id"]
    LOG.info("[%s] GitLab project: %s (ID: %s)", project.label, project.name, project.project_id)
    endpoint = f"/projects/{project.project_id}/repository"
    project.source_sha = api.request("GET", endpoint + "/branches/" + quote(args.source, safe=""))["commit"]["id"]
    project.target_sha = api.request("GET", endpoint + "/branches/" + quote(args.target, safe=""))["commit"]["id"]
    comparison = api.request("GET", endpoint + "/compare", query={"from": project.target_sha, "to": project.source_sha})
    if comparison.get("compare_timeout") or not isinstance(comparison.get("commits"), list):
        raise OperationError("Branch comparison did not complete; the preview is unreliable.")
    project.commits = len(comparison["commits"])
    project.status = "planned" if project.commits else "no_changes"


def prepare_project(project: Project, args):
    path = Path(project.path)
    clean_repository(path, args.git_timeout)
    source_ref = f"refs/remotes/{args.remote}/{args.source}"
    target_ref = f"refs/remotes/{args.remote}/{args.target}"
    git(path, "fetch", "--no-tags", args.remote,
        f"+refs/heads/{args.source}:{source_ref}", f"+refs/heads/{args.target}:{target_ref}", timeout=args.git_timeout)
    fetched = git(path, "rev-parse", source_ref).stdout.strip()
    if fetched != project.source_sha or git(path, "rev-parse", target_ref).stdout.strip() != project.target_sha:
        raise OperationError("A remote branch changed after the preview; rerun and approve the plan again.")
    local_ref = f"refs/heads/{args.source}"
    exists = git(path, "show-ref", "--verify", "--quiet", local_ref, check=False)
    if exists.returncode == 0:
        ahead = int(git(path, "rev-list", "--count", f"{source_ref}..{local_ref}").stdout.strip())
        if ahead:
            raise OperationError(f"Local branch {args.source} has {ahead} commits not present on the remote.")
        git(path, "checkout", args.source, timeout=args.git_timeout)
    elif exists.returncode == 1:
        git(path, "checkout", "--no-track", "-b", args.source, source_ref, timeout=args.git_timeout)
    else:
        raise OperationError("Could not check the local branch.")
    git(path, "-c", "pull.rebase=false", "pull", "--ff-only", "--no-tags", args.remote,
        f"refs/heads/{args.source}", timeout=args.git_timeout)
    if git(path, "rev-parse", "HEAD").stdout.strip() != project.source_sha:
        raise OperationError("The source branch changed during pull; a new preview is required.")
    branch = git(path, "symbolic-ref", "--quiet", "--short", "HEAD").stdout.strip()
    if branch != args.source:
        raise OperationError(f"Not on the expected branch after checkout/pull: {branch}")
    clean_repository(path, args.git_timeout)
    project.prepared_sha = project.source_sha
    success("[%s] Branch %s is up to date: local HEAD = approved remote commit (%s).",
            project.label, branch, project.prepared_sha[:12])


def verify_remote_snapshot(project: Project, api: GitLab, args):
    endpoint = f"/projects/{project.project_id}/repository/branches/"
    for branch, expected in ((args.source, project.source_sha), (args.target, project.target_sha)):
        actual = api.request("GET", endpoint + quote(branch, safe=""))["commit"]["id"]
        if actual != expected:
            raise OperationError(f"Branch {branch} changed after approval; rerun for this project.")


def find_open_mr(project: Project, api: GitLab, args):
    matches = api.all(f"/projects/{project.project_id}/merge_requests", {
        "state": "opened", "scope": "all", "source_branch": args.source, "target_branch": args.target,
    })
    matches = [mr for mr in matches if mr.get("source_project_id") == project.project_id
               and mr.get("target_project_id") == project.project_id]
    if len(matches) > 1:
        raise OperationError("Multiple open MRs exist for the same branch pair; review them manually.")
    return matches[0] if matches else None


def process_mr(project: Project, api: GitLab, approver: GitLab | None, args):
    verify_remote_snapshot(project, api, args)
    endpoint = f"/projects/{project.project_id}/merge_requests"
    mr = find_open_mr(project, api, args)
    if mr:
        LOG.info("[%s] Using the existing MR.", project.label)
    else:
        try:
            mr = api.request("POST", endpoint, data={
                "source_branch": args.source, "target_branch": args.target,
                "title": f"{args.source} → {args.target}",
                "description": f"Created by gitlab-promote.\n\nSource commit: `{project.source_sha}`\nTarget commit: `{project.target_sha}`",
                "remove_source_branch": False,
            })
        except APIError as exc:
            if exc.status not in {0, 409, 422, 500, 502, 503, 504}:
                raise
            # The response may be lost or another process may have created the MR; do not retry POST.
            mr = find_open_mr(project, api, args)
            if not mr:
                raise exc
    project.mr_iid, project.mr_url = mr["iid"], mr["web_url"]
    project.status = "mr_open"
    mr_link(project)
    mr_path = f"{endpoint}/{project.mr_iid}"
    deadline = time.monotonic() + args.merge_timeout
    approved = False
    previous_status = None
    merge_requested = False
    last_wait_remaining = args.merge_timeout
    while True:
        mr = api.request("GET", mr_path)
        if mr.get("state") == "merged":
            project.status, project.detail = "merged", "Merge completed and verified through GitLab."
            return
        if mr.get("state") != "opened":
            raise OperationError(f"MR is not open: {mr.get('state')}")
        if mr.get("sha") != project.source_sha:
            raise OperationError("The MR source commit does not match the approved commit.")
        status = mr.get("detailed_merge_status", "unknown")
        if status != previous_status:
            readable = {"checking": "Checking for conflicts", "unchecked": "Waiting for checks",
                        "preparing": "Preparing MR", "approvals_syncing": "Syncing approvals",
                        "mergeable": "Ready to merge", "conflict": "Merge conflict detected",
                        "ci_still_running": "Pipeline running", "ci_must_pass": "Waiting for a successful pipeline",
                        "not_approved": "Waiting for required approval"}.get(status, status)
            if status == "conflict":
                LOG.error("[%s] %s", project.label, readable)
            else:
                LOG.info("[%s] %s", project.label, readable)
            previous_status = status
        if status == "conflict" or mr.get("has_conflicts") is True:
            project.status, project.detail = "conflict", "Merge conflict detected; MR left open."
            return
        transient = status in {"checking", "unchecked", "approvals_syncing", "preparing"}
        if args.mode == "mr-only" and not transient and status != "unknown":
            project.status, project.detail = "mr_created", f"MR ready; GitLab status: {status}."
            return
        if mr.get("draft") or mr.get("work_in_progress"):
            project.status, project.detail = "blocked", "MR is a draft; manual review is required."
            return
        if status == "not_approved" and approver and not approved:
            # GitLab may reset approval granted before diff preparation is complete.
            versions = api.all(mr_path + "/versions")
            ready = bool(versions and versions[0].get("head_commit_sha") == project.source_sha
                         and versions[0].get("patch_id_sha"))
            if ready:
                approver.request("POST", mr_path + "/approve", data={"sha": project.source_sha})
                approved = True
                success("[%s] MR approved on behalf of the account.", project.label)
                continue
            transient = True
        if status == "mergeable" and not merge_requested:
            verify_remote_snapshot(project, api, args)
            try:
                api.request("PUT", mr_path + "/merge", data={"sha": project.source_sha,
                                                            "should_remove_source_branch": False})
            except APIError as exc:
                # If the result is uncertain, only read; do not send a second merge request.
                if exc.status not in {0, 500, 502, 503, 504}:
                    raise
                LOG.warning("[%s] No merge response received; checking server status.", project.label)
            merge_requested = True
        elif not transient and status not in {"mergeable", "ci_still_running", "ci_must_pass", "merge_time"}:
            project.status, project.detail = "blocked", f"GitLab merge blocker: {status}. MR left open."
            return
        pipeline = mr.get("head_pipeline") or {}
        if status in {"ci_still_running", "ci_must_pass"} and pipeline.get("status") in {"failed", "canceled", "skipped", "manual"}:
            project.status, project.detail = "blocked", f"Pipeline: {pipeline['status']}. MR left open."
            return
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            project.status = "merge_unconfirmed" if merge_requested else "timeout"
            project.detail = f"Did not complete within {args.merge_timeout:g} seconds (status: {status}); check GitLab."
            return
        if last_wait_remaining - remaining >= 15:
            LOG.info("[%s] Waiting: %s | %.0f seconds remaining", project.label, status, remaining)
            last_wait_remaining = remaining
        with activity(f"{project.label} | MR !{project.mr_iid} | {status}"):
            time.sleep(min(args.poll_interval, remaining))


def save_report(path: Path, projects: list[Project], args, outcome: str):
    notifier = getattr(args, "chat", None)
    report = {"time": datetime.now(timezone.utc).isoformat(), "root": str(args.root),
              "source": args.source, "target": args.target, "mode": args.mode,
              "workflow": getattr(args, "workflow", "traditional"),
              "gitlab_url": args.gitlab_url, "account": getattr(args, "account", None),
              "approval_account": getattr(args, "approval_account", None),
              "notifications": {"enabled": notifier is not None, "sent": notifier.sent if notifier else 0,
                                "failed": notifier.failed if notifier else 0},
              "outcome": outcome, "projects": [asdict(p) for p in projects]}
    if hasattr(args, "workflow_stages"):
        report["stages"] = args.workflow_stages
    temp = path.with_suffix(".tmp")
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        stream.write(redact(json.dumps(report, ensure_ascii=False, indent=2)) + "\n")
    os.replace(temp, path)


def pause_between(index: int, total: int, delay: float):
    if index < total - 1 and delay:
        LOG.info("Waiting %g seconds before the next project.", delay)
        with activity("Moving to the next project", duration=delay):
            time.sleep(delay)


def run(args, api: GitLab, approver: GitLab | None, report_path: Path,
        selected_paths: list[Path] | None = None) -> int:
    projects: list[Project] = []
    outcome = "running"
    reported_project_failure = False
    try:
        section("2/5 — Scanning projects: %s", args.root)
        if selected_paths is None:
            with activity("Scanning project directories"):
                paths = discover(args.root, args.include, args.exclude)
        else:
            paths = selected_paths
        if not paths:
            raise OperationError("No Git projects found; check --root and the filters.")
        projects = [Project(str(path), relative_path=path.relative_to(args.root).as_posix()) for path in paths]
        selected = select_projects(projects, args) if selected_paths is None else projects
        if not selected:
            outcome = "cancelled"
            LOG.info("The user cancelled project selection.")
            return 0
        section("3/5 — Checking selected projects")
        seen = set()
        for index, project in enumerate(selected):
            progress("Preflight", index, len(selected), f"Checking: {project.path}")
            try:
                inspect_project(project, api, args)
                if project.project_id in seen:
                    raise OperationError("Multiple local copies of the same GitLab project found; exclude one with --exclude.")
                seen.add(project.project_id)
            except (OperationError, KeyError, TypeError, ValueError) as exc:
                record_project_error(project, "preflight_error", exc)
                LOG.error("[%s] %s", project.label, exc)
                notify_error(args, "Preflight", str(exc), project)
                reported_project_failure = True
            progress("Preflight", index + 1, len(selected), STATUS_LABELS[project.status], project.status)
        section("Operation plan | %s → %s | %s | %s projects", args.source, args.target, args.mode, len(selected))
        for project in selected:
            label = project.label
            detail = project.detail or (f"{project.commits} source commits; current branch: {project.current_branch}")
            LOG.log(logging.ERROR if project.status == "preflight_error" else logging.INFO,
                    "%s | %s | %s", label, STATUS_LABELS[project.status], detail)
        save_report(report_path, projects, args, "preview")
        if any(p.status == "preflight_error" for p in selected):
            raise OperationError("Preflight failed. No checkout, pull, or MR operations were performed on any project.")
        if args.dry_run:
            outcome = "dry_run"
            success("Dry run completed; projects and GitLab were not modified.")
            return 0
        if not args.yes:
            if not sys.stdin.isatty():
                raise OperationError("Non-interactive use requires explicit approval with --yes; use --dry-run for a preview.")
            if not ask_yes_no(f"\nStart {args.source} → {args.target} ({args.mode}) for {len(selected)} selected projects?"):
                outcome = "cancelled"
                LOG.info("The user cancelled the operation.")
                return 0
        section("4/5 — Git preparation: checkout/pull in selected projects")
        for index, project in enumerate(selected):
            progress("Git preparation", index, len(selected), f"Checkout/pull: {project.label}")
            try:
                prepare_project(project, args)
                project.status = "prepared" if project.commits else "no_changes"
                save_report(report_path, projects, args, outcome)
            except OperationError as exc:
                record_project_error(project, "git_error", exc)
                notify_error(args, "Checkout/pull", str(exc), project)
                reported_project_failure = True
                raise OperationError(f"[{project.label}] Preparation failed; the entire operation stopped. No MRs have been created yet. {exc}") from exc
            progress("Git preparation", index + 1, len(selected), f"Ready: {project.label}", project.status)
            pause_between(index, len(selected), args.delay)
        # Recheck the approved state of every project before creating the first MR.
        for project in selected:
            try:
                verify_remote_snapshot(project, api, args)
            except (OperationError, KeyError, TypeError, ValueError) as exc:
                record_project_error(project, "preflight_error", exc)
                notify_error(args, "Remote branch verification", str(exc), project)
                reported_project_failure = True
                raise
        section("5/5 — Merge request operations")
        active = [p for p in selected if p.commits]
        if not active:
            LOG.info("No commits to promote in the selected projects; no MRs are needed.")
        for index, project in enumerate(active):
            progress("MR operations", index, len(active), f"Processing: {project.label}")
            project.status = "processing"
            save_report(report_path, projects, args, outcome)
            try:
                process_mr(project, api, approver, args)
            except (OperationError, KeyError, TypeError, ValueError) as exc:
                record_project_error(project, "mr_error", exc)
            if project.status in {"merged", "mr_created"}:
                success("[%s] %s: %s", project.label, STATUS_LABELS[project.status], project.detail)
            else:
                LOG.error("[%s] %s: %s", project.label, STATUS_LABELS[project.status], project.detail)
                notify_error(args, STATUS_LABELS[project.status], project.detail, project)
            mr_link(project)
            save_report(report_path, projects, args, outcome)
            progress("MR operations", index + 1, len(active), f"{project.label}: {STATUS_LABELS[project.status]}", project.status)
            pause_between(index, len(active), args.delay)
        failed = any(p.status not in {"merged", "mr_created", "no_changes"} for p in selected)
        outcome = "partial_failure" if failed else "completed"
        return 1 if failed else 0
    except KeyboardInterrupt:
        outcome = "interrupted"
        LOG.error("Operation interrupted. Completed operations are not rolled back; check the latest MR status in GitLab.")
        return 130
    except (OperationError, OSError, EOFError, KeyError, TypeError, ValueError) as exc:
        outcome = "aborted"
        LOG.error("Operation stopped: %s", exc)
        if not reported_project_failure:
            notify_error(args, "Overall operation", str(exc))
        return 2
    finally:
        args.last_outcome = outcome
        show_summary(projects, outcome)
        notifier = getattr(args, "chat", None)
        if notifier:
            LOG.info("Google Chat notifications | Sent: %s | Failed: %s", notifier.sent, notifier.failed)
        save_report(report_path, projects, args, outcome)
        LOG.info("Detailed log: %s", report_path.with_suffix(".log"))
        LOG.info("JSON report: %s", report_path)


def run_end_to_end(args, api: GitLab, approver: GitLab | None, report_path: Path) -> int:
    projects: list[Project] = []
    args.workflow_stages = []
    stages = getattr(args, "end_to_end_stages", END_TO_END_STAGES)
    route = " -> ".join([stages[0][0]] + [target for _, target in stages])
    outcome = "running"
    try:
        section("End-to-end promotion | %s", route)
        LOG.info("%s", END_TO_END_NOTE)
        with activity("Scanning project directories"):
            paths = discover(args.root, args.include, args.exclude)
        if not paths:
            raise OperationError("No Git projects found; check --root and the filters.")
        projects = [Project(str(path), relative_path=path.relative_to(args.root).as_posix()) for path in paths]
        selected = select_projects(projects, args)
        if not selected:
            outcome = "cancelled"
            LOG.info("The user cancelled project selection.")
            return 0
        if not args.dry_run and not args.yes:
            if not sys.stdin.isatty():
                raise OperationError("Non-interactive use requires explicit approval with --yes.")
            if not ask_yes_no(f"\nStart {route} for {len(selected)} selected projects, with 30-second waits between stages?"):
                outcome = "cancelled"
                LOG.info("The user cancelled the operation.")
                return 0
        selected_paths = [Path(project.path) for project in selected]
        if args.dry_run:
            LOG.info("Dry run previews each branch pair as it exists now; later stages do not simulate earlier merges. No stage waits are performed.")
        for index, (source, target) in enumerate(stages):
            stage_args = copy(args)
            # The complete route was approved once; keep the same project selection.
            stage_args.source, stage_args.target = source, target
            stage_args.yes = True
            del stage_args.workflow_stages
            stage_path = report_path.with_name(f"{report_path.stem}-{quote(source, safe='')}-to-{quote(target, safe='')}.json")
            section("End-to-end stage %s/%s | %s -> %s", index + 1, len(stages), source, target)
            result = run(stage_args, api, approver, stage_path, selected_paths=selected_paths)
            args.workflow_stages.append({"source": source, "target": target,
                                         "outcome": stage_args.last_outcome, "report": str(stage_path)})
            save_report(report_path, projects, args, "running")
            if result or stage_args.last_outcome not in {"completed", "dry_run"}:
                outcome = stage_args.last_outcome
                LOG.error("End-to-end promotion stopped at %s -> %s; later stages were not started.", source, target)
                return result
            if index < len(stages) - 1 and not args.dry_run:
                LOG.info("Waiting 30 seconds before %s -> %s.", *stages[index + 1])
                with activity("Waiting before the next promotion stage", duration=END_TO_END_DELAY):
                    time.sleep(END_TO_END_DELAY)
        outcome = "dry_run" if args.dry_run else "completed"
        success("End-to-end %s completed.", "preview" if args.dry_run else "promotion")
        return 0
    except KeyboardInterrupt:
        outcome = "interrupted"
        LOG.error("End-to-end promotion interrupted. Completed operations are not rolled back.")
        return 130
    except (OperationError, OSError, EOFError, KeyError, TypeError, ValueError) as exc:
        outcome = "aborted"
        LOG.error("End-to-end promotion stopped: %s", exc)
        notify_error(args, "End-to-end operation", str(exc))
        return 2
    finally:
        save_report(report_path, projects, args, outcome)
        LOG.info("End-to-end JSON report: %s", report_path)


def finite_number(value: str) -> float:
    number = float(value)
    if not math.isfinite(number) or number < 0:
        raise argparse.ArgumentTypeError("Enter a finite, non-negative number.")
    return number


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parent, help="Parent directory containing projects; subdirectories are discovered automatically")
    parser.add_argument("--workflow", choices=["traditional", "end-to-end"],
                        help="Workflow mode; interactive startup offers a menu before branch selection")
    parser.add_argument("--source", help="Source branch; if omitted, a menu opens after settings")
    parser.add_argument("--target", help="Target branch; specify together with --source")
    parser.add_argument("--gitlab-url", default=os.environ.get("GITLAB_URL"), help="GitLab HTTPS URL; precedence: this option, GITLAB_URL, settings.json, terminal input")
    parser.add_argument("--remote", default="origin", help="Git remote name")
    parser.add_argument("--token-source", choices=["settings", "environment"], default="settings",
                        help="Prefer settings.json (fall back to GITLAB_TOKEN if empty), or explicitly use GITLAB_TOKEN")
    parser.add_argument("--ssh-host", help="Host or SSH config alias if the GitLab SSH server differs")
    parser.add_argument("--include", action="append", default=[], help="Project name/relative path glob filter; may be repeated")
    parser.add_argument("--exclude", action="append", default=[], help="Name/relative path glob filter to exclude; may be repeated")
    parser.add_argument("--mode", choices=["merge", "mr-only"], default="merge", help="Create and merge an MR, or only create an MR")
    parser.add_argument("--approve", action="store_true", help="Grant GitLab approval on behalf of an eligible account if needed")
    parser.add_argument("--delay", type=finite_number, default=2, help="Delay between projects in both stages (seconds)")
    parser.add_argument("--merge-timeout", type=finite_number, default=300, help="MR/pipeline wait timeout per project")
    parser.add_argument("--poll-interval", type=finite_number, default=3, help="MR status polling interval (seconds)")
    parser.add_argument("--git-timeout", type=finite_number, default=120, help="Git command timeout (seconds)")
    parser.add_argument("--api-timeout", type=finite_number, default=30, help="HTTP request timeout (seconds)")
    parser.add_argument("--ca-file", help="Custom CA certificate file for self-managed GitLab")
    parser.add_argument("--log-dir", type=Path, default=default_log_directory(), help="Log and JSON report directory")
    parser.add_argument("--color", choices=["auto", "always", "never"], default="auto", help="Terminal colors; auto mode detects the terminal")
    parser.add_argument("--no-progress", action="store_true", help="Disable animated wait indicators; stage progress remains visible as text")
    parser.add_argument("--no-chat", action="store_true", help="Disable Google Chat webhook prompts and notifications")
    parser.add_argument("--chat-timeout", type=finite_number, default=10, help="Google Chat notification request timeout (seconds)")
    parser.add_argument("--dry-run", action="store_true", help="Read-only preflight/plan; a token is required")
    parser.add_argument("--yes", action="store_true", help="Skip account and project prompts; approve all filtered projects and the plan (URL/token required)")
    args = parser.parse_args(argv)
    args.root = args.root.expanduser().resolve()
    args.log_dir = args.log_dir.expanduser().resolve()
    if not args.root.is_dir():
        parser.error("--root must be an existing directory.")
    if (args.source is None) != (args.target is None):
        parser.error("Specify --source and --target together, or omit both to use the menu.")
    if args.workflow == "end-to-end":
        if args.source is not None:
            parser.error("End-to-end mode uses a route; omit --source and --target.")
        if args.mode != "merge":
            parser.error("End-to-end mode requires --mode merge.")
    if not shutil.which("git"):
        parser.error("Git is not installed.")
    if args.source is not None:
        try:
            validate_branches(args.source, args.target)
        except OperationError as exc:
            parser.error(str(exc))
    if not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]*", args.remote):
        parser.error("Invalid remote name.")
    if args.gitlab_url:
        try:
            args.gitlab_url = validate_url(args.gitlab_url)
        except OperationError as exc:
            parser.error(str(exc))
    for key in ("merge_timeout", "poll_interval", "git_timeout", "api_timeout", "chat_timeout"):
        if getattr(args, key) <= 0:
            parser.error(f"--{key.replace('_', '-')} must be greater than zero.")
    return args


def main(argv=None) -> int:
    configure_console()
    args = parse_args(argv)
    try:
        log_path, report_path = setup_logging(args.log_dir, color=args.color, animate=not args.no_progress)
        LOG.info("Log file: %s", log_path)
        with run_lock():
            configure_settings(args)
            select_workflow(args)
            args.chat = configure_chat(args)
            api, approver = configure_accounts(args)
            if args.workflow == "end-to-end":
                return run_end_to_end(args, api, approver, report_path)
            return run(args, api, approver, report_path)
    except KeyboardInterrupt:
        LOG.error("Operation interrupted.")
        return 130
    except (OperationError, OSError, ValueError, EOFError) as exc:
        LOG.error("%s", exc)
        notify_error(args, "Startup or reporting", str(exc))
        return 2


if __name__ == "__main__":
    sys.exit(main())
