# NIGHTHAWK

## Advanced Network Scanner

NIGHTHAWK is a dark, terminal-style graphical interface for [Nmap](https://nmap.org/). It provides a convenient way to run common Nmap scan modes, view the exact command being executed, and monitor live scan output without freezing the interface.

> **Use responsibly:** Only scan systems and networks that you own or have explicit permission to test. Unauthorized scanning may be illegal or disruptive.

## Author

Created by [Ratnadeep Bose](https://github.com/R4tnadeepBose).

## Features

- Dark hacker-style terminal interface.
- TCP Connect scan.
- TCP SYN scan.
- UDP scan.
- FIN, Xmas, NULL, and ACK scans.
- Service and version detection.
- Optional OS detection.
- Custom Nmap options.
- Custom start and end port range.
- Aggressive Nmap timing profile (`-T5`).
- Live command output.
- Visible **COMMAND RUN** field.
- Animated loading bar while a scan is running.
- Abort button to stop a running scan.
- Responsive interface while Nmap is working.

## How It Works

NIGHTHAWK is a graphical front end for Nmap. It does not reimplement packet
scanning in Python. Instead, it builds a validated Nmap command from the
settings selected in the interface and starts Nmap as a separate process.

The scan flow is:

1. You enter a target and port range.
2. NIGHTHAWK validates the target, port values, and extra options.
3. The selected scan type is converted to an Nmap flag.
4. NIGHTHAWK adds the selected detection options and aggressive timing mode.
5. The complete command is shown in **COMMAND RUN**.
6. Nmap performs the scan using its optimized networking engine.
7. Nmap output is streamed into the NIGHTHAWK terminal window in real time.
8. The loading bar runs while the Nmap process is active.
9. **ABORT** terminates the Nmap process when you stop the scan.

For example, these settings:

```text
Scan type: TCP Connect
Ports: 1 - 1024
Service detection: enabled
Target: 127.0.0.1
```

produce a command similar to:

```text
nmap -sT -T5 -p 1-1024 -sV 127.0.0.1
```

NIGHTHAWK starts Nmap with a subprocess argument list rather than passing the
command through a shell. This keeps command arguments separated when the
process is started.

## Requirements

- Windows, macOS, or Linux.
- Python 3.9 or newer.
- Tkinter (included with most Python installers, but packaged separately on
  some Linux distributions).
- Nmap 7.x or newer.

Python's standard library is used, so no `pip install` command is required.

## Installation

### 1. Install Python

Download Python from [python.org/downloads](https://www.python.org/downloads/)
or use your operating system's package manager. During Windows installation,
enable **Add Python to PATH**.

Verify Python:

Windows:

```powershell
py --version
```

macOS or Linux:

```bash
python3 --version
```

### 2. Install Nmap

### Windows

1. Download the installer from [nmap.org/download](https://nmap.org/download.html).
2. Install Nmap.
3. During installation, enable the option to add Nmap to `PATH` if available.
4. Open a new PowerShell window and verify:

   ```powershell
   nmap --version
   ```

If `nmap` is not recognized, add the Nmap installation folder to the Windows `PATH`. The default folder is usually:

```text
C:\Program Files (x86)\Nmap
```

You can add the default folder to `PATH` for the current PowerShell session:

```powershell
$env:Path += ";C:\Program Files (x86)\Nmap"
```

### Ubuntu or Debian

```bash
sudo apt update
sudo apt install nmap python3 python3-tk
```

### Fedora

```bash
sudo dnf install nmap python3 python3-tkinter
```

### macOS

With Homebrew:

```bash
brew install nmap
```

Python and Tkinter may also need to be installed separately depending on the
Python distribution:

```bash
brew install python
```

### Arch Linux

```bash
sudo pacman -Syu nmap python tk
```

### openSUSE

```bash
sudo zypper install nmap python3 python3-tk
```

### Alpine Linux

```bash
apk add nmap python3 py3-tkinter
```

If your distribution uses a different package name for Tkinter, search for
the package containing `tkinter` or `python3-tk`.

### 3. Verify Nmap and Tkinter

Verify Nmap:

```bash
nmap --version
```

Windows PowerShell:

```powershell
py -c "import tkinter; print('Tkinter OK')"
```

macOS or Linux:

```bash
python3 -c "import tkinter; print('Tkinter OK')"
```

## Download or Clone

Clone the repository:

```bash
git clone https://github.com/r4tnadeepbose/NIGHTHAWK.git
cd NIGHTHAWK
```

You can also download the repository as a ZIP file from
[NIGHTHAWK on GitHub](https://github.com/r4tnadeepbose/NIGHTHAWK) and extract it.

## Run NIGHTHAWK on Windows

Open PowerShell in the project directory:

```powershell
cd "C:\path\to\nighthawk"
```

Run with the Python launcher:

```powershell
py .\scanner.py
```

If `py` is unavailable:

```powershell
python .\scanner.py
```

## Run NIGHTHAWK on macOS

```bash
cd /path/to/nighthawk
python3 scanner.py
```

## Run NIGHTHAWK on Linux

```bash
cd /path/to/nighthawk
python3 scanner.py
```

The script does not need to be installed system-wide. Running it from the
project directory is enough.

## Using the Application

1. Enter a hostname or IP address in **TARGET**.
2. Enter the first and last ports in **PORT RANGE**.
3. Select a scan type.
4. Enable **SERVICE / VERSION DETECTION** if required.
5. Enable **OS DETECTION** when appropriate.
6. Add optional Nmap arguments in **EXTRA OPTIONS**.
7. Click **LAUNCH SCAN**.
8. Review the exact command in **COMMAND RUN** and the live output below it.
9. Click **ABORT** to stop the scan.

For a safe local test, use:

```text
Target: 127.0.0.1
Ports: 1 - 1024
Scan type: TCP Connect
```

## Example Commands

The GUI builds commands similar to these:

```text
nmap -sT -T5 -p 1-1024 -sV 127.0.0.1
```

TCP SYN scan:

```text
nmap -sS -T5 -p 1-1024 -sV 192.168.1.1
```

UDP scan:

```text
nmap -sU -T5 -p 53,123,161 192.168.1.1
```

Service and OS detection:

```text
nmap -sT -T5 -p 1-1024 -sV -O 192.168.1.10
```

NSE script through **EXTRA OPTIONS**:

```text
--script vuln
```

Some scan types, including SYN, UDP, and OS detection, may require Administrator/root privileges.

### Privilege requirements

- **TCP Connect (`-sT`)** usually works as a normal user.
- **TCP SYN (`-sS`)** generally requires Administrator/root privileges.
- **UDP (`-sU`)** can be slow and may require elevated privileges.
- **FIN, Xmas, NULL, and ACK** scans may require raw packet privileges.
- **OS detection (`-O`)** commonly requires Administrator/root privileges.

On Windows, start PowerShell or VS Code as **Administrator** only when an
authorized scan requires it. On macOS or Linux, use `sudo` only for an
authorized target and launch the application with the appropriate privileges:

```bash
sudo python3 scanner.py
```

Do not use elevated privileges unless the selected Nmap scan mode requires
them.

## Common Problems

### `Nmap was not found`

Verify that Nmap is installed and available on `PATH`:

```powershell
nmap --version
```

After changing `PATH`, restart the terminal or VS Code.

NIGHTHAWK checks `PATH` with Python's `shutil.which("nmap")`. Installing Nmap
is not enough if the terminal or VS Code process cannot find the executable.

### `python` or `python3` is not recognized

Install Python and reopen the terminal. On Windows, try:

```powershell
py .\scanner.py
```

### The GUI does not open

This normally means Tkinter is missing. Install the Tkinter package listed for
your operating system above, then repeat the Tkinter verification command.

### Nmap says a scan requires privileges

Use the TCP Connect scan as a normal-user test, or rerun the application with
the required Administrator/root privileges. Only scan systems for which you
have permission.

### Permission errors

Run the terminal or application with appropriate administrator/root privileges for scans that require raw packet access. Only do this for authorized testing.

### Tkinter is missing

On Linux, install the Tkinter package for your Python version:

```bash
sudo apt install python3-tk
```

### The scan appears slow

UDP scans and service detection normally take longer than a basic TCP connect scan. Reduce the port range for testing, or disable service and OS detection when they are not needed.

## Validate the Python File

Before running, check the script for syntax errors:

### Windows PowerShell

```powershell
python -m py_compile .\scanner.py
```

### macOS or Linux

```bash
python3 -m py_compile scanner.py
```

## Project Structure

```text
.
├── scanner.py
└── README.md
```

## License

Add the license you want to use before publishing the repository. MIT is a common choice for small open-source utilities.

## Disclaimer

NIGHTHAWK is a front end for Nmap. The author is not responsible for misuse, damage, service interruption, or unauthorized activity. Always obtain written permission before scanning a target you do not own.
