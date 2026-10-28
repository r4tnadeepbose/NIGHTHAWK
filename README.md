
# NIGHTHAWK

**Advanced Network Scanner — a terminal-style GUI front end for Nmap**

NIGHTHAWK is a dark, terminal-inspired graphical interface for Nmap. It lets you run common scan modes, see the exact command being executed, watch live output stream into the window, and get automatic HTML/JSON/CSV/TXT reports — all without freezing the UI.

> **Use responsibly.** Only scan systems and networks you own or have explicit written permission to test. Unauthorized scanning may be illegal or disruptive.

**Author:** Ratnadeep Bose

---

## Features

- Dark hacker-style terminal interface
- Scan types: TCP Connect, TCP SYN, UDP, FIN, Xmas, NULL, ACK, Window, Maimon, Ping Discovery, IP Protocol, and Custom
- Service/version detection and optional OS detection
- Custom scan mode for your own flags
- Single ports, ranges, or comma-separated port lists (`443`, `1-1024`, `22,80,443`)
- Aggressive `-T5` timing profile
- Live command output streamed in real time (clean output, hidden Nmap banners)
- Visible **COMMAND RUN** field showing the assembled command
- Animated loading bar and an **ABORT** button
- Per-control help (the `?` button)
- Automatic HTML, JSON, CSV, and TXT reports
- Built-in export/download buttons directly inside the HTML report page
- Responsive interface while Nmap runs

---

## How It Works

NIGHTHAWK is a GUI front end — it does **not** reimplement packet scanning in Python. It builds a validated Nmap command from your settings and runs Nmap as a separate process, streaming its output back into the window.

**Scan flow:**

1. Enter a target and port expression.
2. NIGHTHAWK validates the target, ports, and extra options.
3. The selected scan type is converted to an Nmap flag.
4. Selected detection options and `-T5` are appended.
5. The full command is shown in **COMMAND RUN**.
6. Nmap performs the scan.
7. Output streams into the terminal window in real time.
8. The progress bar runs while the process is active.
9. XML scan data is converted into portable reports.
10. **ABORT** terminates the Nmap process on demand.

For example, these settings:

```text
Scan type: TCP Connect
Ports: 1-1024
Service detection: enabled
Target: 127.0.0.1
```

produce:

```text
nmap -sT -T5 -sV -p 1-1024 -oX <temp.xml> 127.0.0.1
```

NIGHTHAWK launches Nmap with a subprocess argument list rather than a shell, so arguments stay separated and shell injection is avoided.

---

## Requirements

- Windows, macOS, or Linux
- Python 3.9+
- Tkinter (bundled with most Python installers; packaged separately on some Linux distros)
- Nmap 7.x+

Only the Python standard library is used — no `pip install` needed.

---

## Installation

### 1. Install Python

Download from [python.org/downloads](https://www.python.org/downloads/) or use your package manager. On Windows, enable **Add Python to PATH** during installation.

Verify:

```powershell
py --version
```

```bash
python3 --version
```

### 2. Install Nmap

**Windows**

1. Download the installer from [nmap.org/download](https://nmap.org/download.html).
2. Install Nmap (enable the PATH option if offered).
3. Open a new PowerShell window and verify:

   ```powershell
   nmap --version
   ```

   If `nmap` isn't recognized, add the install folder to `PATH` (usually `C:\Program Files (x86)\Nmap`):

   ```powershell
   $env:Path += ";C:\Program Files (x86)\Nmap"
   ```

**Ubuntu / Debian**

```bash
sudo apt update
sudo apt install nmap python3 python3-tk
```

**Fedora**

```bash
sudo dnf install nmap python3 python3-tkinter
```

**macOS (Homebrew)**

```bash
brew install nmap python
```

**Arch Linux**

```bash
sudo pacman -Syu nmap python tk
```

**openSUSE**

```bash
sudo zypper install nmap python3 python3-tk
```

**Alpine Linux**

```bash
apk add nmap python3 py3-tkinter
```

If your distro names the Tkinter package differently, search for `tkinter` or `python3-tk`.

### 3. Verify Nmap and Tkinter

```bash
nmap --version
```

```powershell
py -c "import tkinter; print('Tkinter OK')"
```

```bash
python3 -c "import tkinter; print('Tkinter OK')"
```

---

## Download or Clone

```bash
git clone https://github.com/r4tnadeepbose/NIGHTHAWK.git
cd NIGHTHAWK
```

Or download the repository as a ZIP from [GitHub](https://github.com/r4tnadeepbose/NIGHTHAWK) and extract it.

---

## Running NIGHTHAWK

**Windows (PowerShell)**

```powershell
cd "C:\path\to\nighthawk"
py .\scanner.py
```

If `py` is unavailable:

```powershell
python .\scanner.py
```

**macOS**

```bash
cd /path/to/nighthawk
python3 scanner.py
```

**Linux**

```bash
cd /path/to/nighthawk
python3 scanner.py
```

No system-wide install is required — running from the project directory is enough.

---

## Using the Application

1. Enter a hostname or IP in **TARGET**.
2. Enter one port, a range, or a list in **PORTS**: `443`, `1-1024`, or `22,80,443`.
3. Select a **SCAN TYPE**.
4. Enable **SERVICE / VERSION** if needed.
5. Enable **OS DETECTION** when appropriate.
6. Add optional flags in **EXTRA FLAGS**. Select **Custom** to hide standard controls and enter a full flag string in **CUSTOM COMMAND**.
7. Click **▶ LAUNCH ASSESSMENT**.
8. Review the exact command in **COMMAND RUN** and the live output below.
9. Click **■ ABORT** to stop.
10. When complete, the HTML report opens automatically. Reports are saved in `reports/` beside `scanner.py`.

**Safe local test:**

```text
Target: 127.0.0.1
Ports: 1-1024
Scan type: TCP Connect
```

### Reports

Each completed scan produces four files sharing one timestamp:

```text
reports/
├── nighthawk_YYYYMMDD_HHMMSS_<id>.html
├── nighthawk_YYYYMMDD_HHMMSS_<id>.json
├── nighthawk_YYYYMMDD_HHMMSS_<id>.csv
└── nighthawk_YYYYMMDD_HHMMSS_<id>.txt
```

The HTML report opens automatically. It features a live filter box to quickly search by host, port, state, or service. Additionally, the HTML report contains **EXPORT JSON**, **EXPORT CSV**, and **EXPORT TXT** buttons that let you instantly download the data directly from the browser.

---

## Example Commands

TCP Connect with service detection:

```text
nmap -sT -T5 -sV -p 1-1024 127.0.0.1
```

TCP SYN:

```text
nmap -sS -T5 -sV -p 1-1024 192.168.1.1
```

UDP:

```text
nmap -sU -T5 -p 53,123,161 192.168.1.1
```

Service + OS detection:

```text
nmap -sT -T5 -sV -O -p 1-1024 192.168.1.10
```

NSE script via **EXTRA FLAGS**:

```text
--script vuln
```

### Privilege requirements

| Scan | Typical privileges |
|---|---|
| TCP Connect (`-sT`) | Normal user |
| TCP SYN (`-sS`) | Administrator / root |
| UDP (`-sU`) | May require elevated privileges |
| FIN / Xmas / NULL / ACK | Often raw-packet privileges |
| OS detection (`-O`) | Usually Administrator / root |

On Windows, start PowerShell or VS Code as **Administrator** only when an authorized scan needs it. On macOS/Linux, use `sudo` only for authorized targets:

```bash
sudo python3 scanner.py
```

Don't elevate unless the chosen scan mode requires it.

---

## Troubleshooting

### `Nmap was not found`

Confirm Nmap is on `PATH`:

```powershell
nmap --version
```

Restart the terminal or VS Code after changing `PATH`. NIGHTHAWK locates the binary with `shutil.which("nmap")`, so installing Nmap is not enough if the process can't find it.

### `python` / `python3` is not recognized

Install Python and reopen the terminal. On Windows try:

```powershell
py .\scanner.py
```

### The GUI doesn't open

Tkinter is likely missing. Install the Tkinter package for your OS (see above), then re-run the verification command.

### Nmap reports a scan requires privileges

Use TCP Connect for a normal-user test, or rerun with Administrator/root — only for authorized targets.

### Permission errors

Run the terminal or app with appropriate admin/root privileges only for scans that need raw packet access, and only on authorized systems.

### Tkinter missing on Linux

```bash
sudo apt install python3-tk
```

### The scan is slow

UDP and service detection are inherently slower than a basic TCP Connect scan. Narrow the port range, or disable service/OS detection when not needed.

---

## Validate the Script

Before running, check for syntax errors:

```powershell
python -m py_compile .\scanner.py
```

```bash
python3 -m py_compile scanner.py
```

---

## Project Structure

```text
.
├── scanner.py
├── README.md
└── reports/        (created on first scan)
```

---

## License

Add your chosen license before publishing. MIT is a common choice for small open-source utilities.

---

## Disclaimer

NIGHTHAWK is a front end for Nmap. The author is not responsible for misuse, damage, service interruption, or unauthorized activity. Always obtain written permission before scanning any target you do not own.