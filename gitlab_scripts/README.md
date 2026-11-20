# GitLab Promote — User Manual

## 🔵 Description

Updates **multiple selected GitLab projects in sequence** by promoting changes between branches. It uses **Python**, **Git**, and the **GitLab API** to check repositories, update local source branches, and create or reuse merge requests (MRs). It then attempts to merge them according to GitLab's rules.

- **Traditional:** promote one branch pair across your selected projects, for example `dev → demo`.
- **End-to-end:** promote the same selected projects through `dev → demo → beta → main`, or a custom route. It waits **30 seconds between stages**. A failed stage stops the remaining route; completed merges are kept.

## 🟢 Compatible Systems

| System | Verification |
| --- | --- |
| **Linux** | Native Linux support in the code; startup checked on Linux. |
| **Windows** | Native Windows support in the code; no WSL required. Reviewed in code, but not run on Windows here. |

You need **Python 3.10+**, **Git**, network access to GitLab, and local clones with clean working trees and configured Git authentication (SSH or HTTPS). Source and target branches must exist on GitLab. No extra Python packages are needed.

## 💻 How to Use on Every OS

The workflow is the same on **Linux and Windows**. Only the Python command and terminal setup differ.

### 1. Check the tools

Open a **terminal on Linux** or **PowerShell on Windows** and check:

| Check | Linux | Windows |
| --- | --- | --- |
| Python | `python3 --version` | `python --version` |
| Git | `git --version` | `git --version` |

If missing, install **Python 3.10+** and **Git**. On Linux, use your distribution's package manager. On Windows, install Python and Git for Windows with their commands available on `PATH`, then open a new PowerShell window. If Windows exposes Python as `py`, use `py -3` instead of `python`.

### 2. Prepare the folder

Place the script and your cloned repositories together:

```text
projects/
├── gitlab_promote.py
├── settings.json          ← created automatically if missing
├── frontend/
│   ├── atlas/.git/
│   └── beacon/.git/
└── microservices/
    ├── accounts/.git/
    └── billing/.git/
```

The script automatically scans folders beneath its own directory, including nested repositories. Keep this directory writable so it can save settings.

### 3. Start and enter credentials

Open your terminal in that folder and run the command for your system:

| Linux | Windows |
| --- | --- |
| `python3 gitlab_promote.py` | `python gitlab_promote.py` |

**On the first run, credentials are requested before the menus:**

![First startup: GitLab URL and hidden access token prompt, using example values](images/first-run-credentials.png)

*Example screenshot: `devops` is a sample username; paths and server addresses use mock values.*

| Prompt | What to enter |
| --- | --- |
| **GitLab URL** | Your server address, for example `https://gitlab.example.com`. |
| **GitLab account access token** | A personal access token with **`api` scope**. Input is hidden. Your account needs permission to create and merge MRs in the selected projects. |
| **Google Chat webhook URL** | A Google Chat incoming webhook for error notifications. **Google Chat is optional**, but the current code requires a valid URL when this prompt appears. To skip Chat, add `--no-chat` to your system's launch command above. |

**Get a token:** in GitLab, open your avatar → **Edit profile → Access → Personal access tokens**. Create a token with a name, expiry date, and **`api`** scope; if a token-type menu appears, choose **Legacy token**. Generate it and copy it before leaving the page. See [GitLab's token instructions](https://docs.gitlab.com/user/profile/personal_access_tokens/).

If settings already exist, press **Enter** to keep them or type **n** to edit them. Valid credentials are saved in `settings.json` after account verification. A newly configured webhook may also prompt you to send a real test message: **Enter** sends it; **n** skips it.

> 🔒 `settings.json` stores credentials in plain text. Keep it private and out of version control. Git authentication must already work separately; entering this token does not configure Git credentials.

### 4. Choose the workflow, branches, and projects

The menu examples below follow the same order as the script. All project names in the image are fictional examples.

![Workflow, branch selection, and project selection terminal examples](images/promotion-menus.png)

1. **Workflow menu (top):** choose **1 / Enter** for Traditional mode. To use End-to-end, type **2**, then press **Enter**.
2. **Branch menu (middle):** use **↑ / ↓** and press **Enter**. The default is `dev → demo`. Choose **custom** to enter two branches, such as `dev beta`. In End-to-end mode, choose the default route or **custom**, then enter at least two branch names in order, such as `demo beta main`. Terminals without arrow-key menus show numbered choices; **1 / Enter** selects the first option.
3. **Account verification:** the script checks your credentials with GitLab before listing projects.
4. **Project menu (bottom):** press **Enter** for all projects, type `1,3,5-7` and press **Enter** for specific projects, or type **n** and press **Enter** to cancel.

### 5. Confirm and run

For Traditional mode, review the checks and operation plan, then press **Enter** to start or type **n** to cancel. End-to-end asks you to confirm the entire route before the stage checks begin.

The script processes your selected projects in sequence: it fetches branches, checks out and pulls each source branch, rechecks remote commits, and creates/reuses and attempts to merge MRs. Conflicts or GitLab approval/pipeline rules may leave MRs open. Local repositories remain on the source branch used by the script. The terminal shows progress, MR links, results, and log/report paths.

---

Edited Muhammet İyidil 20.11.2026
