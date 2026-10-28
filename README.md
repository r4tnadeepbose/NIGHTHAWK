
# NIGHTHAWK

**Advanced Network Scanner — a terminal-style GUI front end for Nmap**

NIGHTHAWK is a dark, terminal-inspired graphical interface for Nmap. It provides a convenient way to run complex Nmap scans, execute vulnerability scripts, bypass firewalls, and monitor live scan output without freezing the interface. It features dynamic reporting that automatically adapts to the data you collect.

> **Use responsibly:** Only scan systems and networks that you own or have explicit permission to test. Unauthorized scanning may be illegal or disruptive.

**Author:** [Ratnadeep Bose](https://github.com/R4tnadeepBose)

---

## Features

- **Dark hacker-style interface** with color-coded live output (green for open ports, red for closed).
- **Comprehensive Scan Types:** TCP Connect, SYN, UDP, FIN, Xmas, NULL, ACK, Window, Maimon, and Ping Discovery.
- **Advanced Firewall / IDS Evasion:** Built-in support for packet fragmentation (`-f`), custom MTU, decoy scans (`-D`), MAC spoofing, and bad checksum scans.
- **NSE Script Integration:** Quick checkboxes for `Default (-sC)`, `Vuln`, `HTTP-Enum`, and `SSL-Audit`.
- **Dynamic HTML Reporting:** The HTML report automatically hides columns and info boxes if you didn't scan for them. If you run an NSE script, a dedicated "NSE Output" column appears. 
- **Built-in Cheatsheet:** A one-click reference guide for all Nmap flags, timing templates, and bypass techniques.
- **Live Host Info:** Extracts MAC address and OS details in real-time as Nmap streams them.
- **Subnet Discovery:** Type a CIDR range (e.g., `192.168.1.0/24`) to auto-discover live hosts and select targets.
- **Scan History & Diff Engine:** Compare two past scans to instantly see newly opened or closed ports.
- **Scan Presets:** Save your favorite complex scan configurations to the Profile dropdown.
- **Auto-Save Settings:** Remembers your last target, ports, and preferences.

---

## How It Works

NIGHTHAWK is a GUI front end — it builds a validated Nmap command from your settings and runs Nmap as a separate process, streaming its output back into the window.

1. Enter a target and port expression (or a CIDR range for discovery).
2. NIGHTHAWK validates the input and constructs the command.
3. The selected scan type (and any evasion flags) are converted to Nmap syntax.
4. Nmap performs the scan, and the output is color-coded in real-time.
5. XML scan data is parsed and converted into dynamic HTML, JSON, CSV, and TXT reports.
6. **ABORT** terminates the Nmap process instantly.

For example, selecting the **Evade Firewall** profile produces:
```text
nmap -f -T2 -sV -p 1-1024 127.0.0.1
```

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
```bash
python3 --version
```

### 2. Install Nmap

**Windows**
1. Download the installer from [nmap.org/download](https://nmap.org/download.html).
2. Install Nmap (enable the PATH option if offered).
3. Verify in PowerShell:
```powershell
nmap --version
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

---

## Download or Clone

```bash
git clone https://github.com/r4tnadeepbose/NIGHTHAWK.git
cd NIGHTHAWK
```

---

## Running NIGHTHAWK

**Windows (PowerShell)**
```powershell
py .\scanner.py
```
If `py` is unavailable, use `python .\scanner.py`.

**macOS / Linux**
```bash
python3 scanner.py
```

---

## Using the Application

1. **Target:** Enter a single IP (`192.168.1.1`), a domain (`example.com`), or a CIDR range (`192.168.1.0/24`).
2. **Ports:** Enter `1-1024`, `22,80,443`, or use the dropdown for `Top 100`, `Top 1000`, or `All`.
3. **Scan Type:** Choose from standard scans or select a **Firewall Evasion** technique (like Fragment or Decoy).
4. **NSE Scripts:** Check the boxes to automatically run vulnerability scans, HTTP enumeration, or SSL audits.
5. Click **▶ LAUNCH**.
6. Review the exact command in **COMMAND RUN** and the live color-coded output below.
7. When complete, the HTML report opens automatically.

### The Cheatsheet
Click the **`? CHEATSHEET`** button in the top right corner at any time to open a modal containing every Nmap switch, flag, and bypass command.

### Reports
Each completed scan produces up to four files sharing one timestamp:
```text
reports/
├── nighthawk_YYYYMMDD_HHMMSS_<id>.html
├── nighthawk_YYYYMMDD_HHMMSS_<id>.json
├── nighthawk_YYYYMMDD_HHMMSS_<id>.csv
└── nighthawk_YYYYMMDD_HHMMSS_<id>.txt
```

**Dynamic HTML Feature:**
If you scan with `-sV` and `--script vuln`, the HTML report will show a "Version" column, an "NSE Output" box detailing CVEs, and a "Host Info" box showing the OS and MAC. If you run a basic Ping Sweep, those columns will automatically hide so your report stays clean.

---

## Example Commands

**Standard Service Detection:**
```text
nmap -sT -T5 -sV -p 1-1024 127.0.0.1
```

**Firewall Evasion (Fragmentation + Decoys):**
```text
nmap -f -D RND:10 -T2 -p 1-1024 192.168.1.1
```

**Vulnerability Scan via NSE:**
```text
nmap -sV --script vuln -p 80,443 192.168.1.10
```

### Privilege requirements

| Scan | Typical privileges |
|---|---|
| TCP Connect (`-sT`) | Normal user |
| TCP SYN (`-sS`) | Administrator / root |
| UDP (`-sU`) | May require elevated privileges |
| OS detection (`-O`) | Usually Administrator / root |
| Fragmentation (`-f`) | Usually requires raw-packet (root) |

---

## Troubleshooting

### `Nmap was not found`
Confirm Nmap is on `PATH`:
```powershell
nmap --version
```
Restart the terminal after changing `PATH`. NIGHTHAWK locates the binary with `shutil.which("nmap")`.

### `python` / `python3` is not recognized
Install Python and reopen the terminal. On Windows try:
```powershell
py .\scanner.py
```

### The GUI doesn't open
Tkinter is likely missing. Install the Tkinter package for your OS (see above).

---

## License

Add your chosen license before publishing. MIT is a common choice for small open-source utilities.

---

## Disclaimer

NIGHTHAWK is a front end for Nmap. The author is not responsible for misuse, damage, service interruption, or unauthorized activity. Always obtain written permission before scanning any target you do not own.