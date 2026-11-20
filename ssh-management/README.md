# manage-ssh

An interactive terminal user interface (TUI) tool written in Python to easily manage, inspect, and connect to SSH hosts defined in your OpenSSH configuration (`~/.ssh/config`).

---

## Features

- **Interactive Menu**: Easily browse through SSH hosts using arrow keys and press `Enter` to connect.
- **Host Details**: Inspect host parameters (`HostName`, `Port`, `User`, `IdentityFile`) via the built-in **INFO** screen.
- **OpenSSH Config Support**: Automatically parses `~/.ssh/config`, `Include` directives, and supports custom config files (`-F`).

---

## Installation & Setup

### 🪟 Windows Setup

#### Prerequisites
- **Python 3**: Check with `python --version`. Ensure Python is added to `PATH`.
- **OpenSSH Client**: Built into Windows 10/11 (verify with `ssh -V`).

#### Step-by-Step Instructions
1. **Install `windows-curses`**:
   ```powershell
   python -m pip install windows-curses
   ```
2. **Save Project Files**: Place `manage-ssh` and `sshm.cmd` in a folder of your choice (e.g., `C:\Tools\ssh-management`).
3. **Add to PATH**:
   - Search for **"Edit environment variables for your account"** in the Windows Start menu.
   - Edit the `Path` variable under User variables and add the folder path from Step 2.
4. **Run**: Open a new terminal and type:
   ```cmd
   sshm
   ```

---

### 🐧 Linux / macOS Setup

#### Prerequisites
- **Python 3**: Check with `python3 --version`.
- **OpenSSH Client**: Check with `ssh -V`.

#### Step-by-Step Instructions
1. **Make Executable**:
   ```bash
   chmod +x manage-ssh
   ```
2. **Create Symlink**:
   ```bash
   mkdir -p ~/.local/bin
   ln -s "$PWD/manage-ssh" ~/.local/bin/sshm
   ```
3. **Add to PATH** (if `~/.local/bin` is not already in your PATH):
   ```bash
   export PATH="$HOME/.local/bin:$PATH"
   ```
4. **Run**: Open any terminal and type:
   ```bash
   sshm
   ```

---

## Usage

### SSH Configuration File

The application reads your OpenSSH configuration file to build the host list. By default, the file must be named **`config`** (without an extension, not `config.txt`) and stored in the `.ssh` folder inside your user home directory:

| Operating system | Default location | Example |
| --- | --- | --- |
| Linux / macOS | `~/.ssh/config` | `/home/alice/.ssh/config` (Linux) |
| Windows | `%USERPROFILE%\.ssh\config` | `C:\Users\Alice\.ssh\config` |

The home directory is determined by Python's `Path.home()`. On Windows, the same file can be accessed as `$HOME\.ssh\config` in PowerShell. The application reads this location regardless of where `manage-ssh` or `sshm.cmd` is installed or which directory you run it from.

Create the `.ssh` folder and the `config` file if they do not exist, then add your SSH hosts, for example:

```sshconfig
Host my-server
    HostName 192.0.2.10
    User deploy
    Port 22
```

Running `sshm` will show `my-server` in the menu. The application also reads files referenced by `Include` directives; relative include paths are resolved from your home directory's `.ssh` folder. Only explicit host aliases are listed; wildcard entries such as `Host *` are not menu items.

To read a different file, use `-F` or `--config`. A custom file can have any name, and its path is also passed to the SSH client for host details and connections:

```bash
# Launch using default SSH config (~/.ssh/config)
sshm

# Launch using a custom SSH config file
sshm -F /path/to/custom_config
```

Windows example (PowerShell or Command Prompt):

```powershell
sshm -F "C:\Users\Alice\.ssh\custom_config"
```

### Controls
- **Up / Down** (or `j` / `k`): Navigate through the host list
- **Enter / Numpad Enter**: Select option / Connect to host
- **INFO**: View detailed host settings
- **EXIT / Esc / q**: Quit the application
