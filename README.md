# NIGHTHAWK

NIGHTHAWK is a desktop Nmap scanner with a Version 2 security dashboard. It provides scan controls, live output, risk assessment, and browser reports without Python package dependencies.

Only scan hosts you own or have permission to test.

## What’s in Version 2

- Dashboard for target details, ports, scripts, live output, exports, and reports.
- Shared risk assessment in the app and HTML report: **Clear**, **Exposed**, **Review**, **High Risk**, and **Critical**.
- Scan history and side-by-side comparison of open-port changes.
- HTML reports with the same layout, logo, severity colors, filtering, and export controls as the dashboard.
- Existing scan types, presets, custom flags, NSE scripts, and subnet discovery are retained.

## Requirements

- Python 3.9 or newer, including Tkinter
- Nmap available on `PATH`
- No `pip install` required

## Linux — Kali/Debian

```bash
git clone https://github.com/r4tnadeepbose/NIGHTHAWK.git
cd NIGHTHAWK
sudo apt update
sudo apt install -y nmap python3 python3-tk
./requirements.txt
./scanner.py
```

Use elevated privileges only for scan types that require raw packets:

```bash
sudo -E ./scanner.py
```

Useful commands:

```bash
make check       # check Python, Tkinter, and Nmap
make man         # preview the manual page
sudo ./install.sh
nighthawk        # available after installation
```

## Windows

1. Download the [NIGHTHAWK ZIP](https://github.com/r4tnadeepbose/NIGHTHAWK/archive/refs/heads/main.zip) and extract it.
2. Install Python 3.9+ from [python.org](https://www.python.org/downloads/) with **Add Python to PATH** enabled.
3. Install Nmap from [nmap.org](https://nmap.org/download.html) and add it to `PATH` during setup.
4. Open PowerShell in the extracted folder and run:

```powershell
cd "$HOME\Downloads\NIGHTHAWK-main"
py .\scanner.py
```

Use `python .\scanner.py` if the `py` launcher is unavailable.

## Using NIGHTHAWK

1. Enter a hostname, IP address, or CIDR range.
2. Choose ports, scan type, timing, and optional NSE scripts.
3. Select **START SCAN**.
4. Review the live log, target information, ports, script output, and risk assessment.
5. Open the browser report or use **Reports** to compare completed scans.

## Reports

Each completed scan writes matching report files to:

```text
reports/nighthawk_YYYYMMDD_HHMMSS_<id>.{html,json,csv,txt}
```

The HTML report contains the dashboard summary, risk status, target details, service table, script output, search filter, and JSON/CSV/TXT export buttons.

## Command-line help

```bash
./scanner.py --help
./scanner.py --version
```

**Author:** Ratnadeep Bose
