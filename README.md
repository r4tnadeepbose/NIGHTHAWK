# NIGHTHAWK 2.0.0

A desktop Nmap scanner with a Version 2 security dashboard. NIGHTHAWK turns command-line network scanning into a point-and-click experience — scan controls, live output, risk assessment, and browser reports — with **zero Python package dependencies**.

> ⚠️ **Only scan hosts you own or have explicit permission to test.** Unauthorized scanning is illegal in most jurisdictions.

---

## Table of Contents

- [What's New in Version 2](#whats-new-in-version-2)
- [Features](#features)
- [How It Works](#how-it-works)
- [Requirements](#requirements)
- [Installation](#installation)
  - [Linux — Kali / Debian / Ubuntu](#linux--kali--debian--ubuntu)
  - [Windows](#windows)
  - [macOS](#macos)
- [Using NIGHTHAWK](#using-nighthawk)
- [Reports](#reports)
- [Command-Line Usage](#command-line-usage)
- [Project Structure](#project-structure)
- [Safety & Security Design](#safety--security-design)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)
- [License](#license)
- [Author](#author)

---

## What's New in Version 2

Version 2 rebuilds the entire interface as a **security-operations dashboard** while keeping every scanner feature from Version 1.

| Area | What changed |
|---|---|
| **Dashboard** | Split layout — sidebar for scan configuration, main panel with Overview / Ports / Scripts / Live / Export tabs |
| **Risk Assessment** | A shared risk engine (Clear · Exposed · Review · High Risk · Critical) now drives both the desktop gauge **and** the HTML report badge |
| **Scan History** | Compare any two saved scans side-by-side; newly opened and closed ports are highlighted |
| **HTML Reports** | Same layout, logo, severity colors, filter box, and export buttons as the in-app dashboard |
| **Summary Cards** | Hosts up · Open ports · Script findings · Scan duration, updated live after every scan |
| **Target Info Panel** | IP · MAC · OS · Network distance · Service info, populated from Nmap XML |
| **Retained** | All scan types, presets, custom flags, NSE scripts, and subnet discovery |

---

## Features

### Scanning
- **11 scan types** — TCP Connect (`-sT`), TCP SYN (`-sS`), UDP (`-sU`), FIN/Xmas/NULL/ACK/Window/Maimon, Ping Discovery (`-sn`), IP Protocol (`-sO`).
- **Firewall / IDS evasion** — packet fragmentation (`-f`), custom MTU, decoys (`-D RND:10`), MAC spoofing, bad checksums, idle scan, source-port spoofing.
- **Timing templates** — `-T0` (Paranoid) through `-T5` (Insane).
- **Service / version detection** (`-sV`) and **OS detection** (`-O`).
- **NSE scripts** — default (`-sC`), vulnerability (`vuln`), HTTP enumeration (`http-enum`), SSL cipher audit (`ssl-enum-cipher`).
- **Custom flags** field for advanced users, with dangerous flags blocked.
- **CIDR subnet sweep** — enter `192.168.1.0/24`, NIGHTHAWK first discovers live hosts, then lets you pick which to scan.
- **Presets** — Quick TCP · Intense Scan · Stealth SYN · Evade Firewall · Ping Sweep.
- **User favorites** — save the current form as a named preset.

### Reporting
- **Four formats written per scan:** `.html` · `.json` · `.csv` · `.txt` — all saved to `reports/`.
- **Interactive HTML report** — severity badge, summary cards, target metadata, port table, script output, live filter box, and JSON/CSV/TXT export buttons.
- **Scan history & diff** — pick any two past scans, see which ports opened or closed between them.

### Usability
- Background scanning — the UI never freezes.
- Live Nmap output streamed into the app with color-coded lines (green = open, yellow = closed/filtered, red = error).
- Live MAC / OS lookup while scanning.
- Auto-open HTML report toggle.
- Config auto-saves to `nighthawk_config.json` — your last target, ports, scan type, and timing are restored next launch.
- Built-in **Nmap cheatsheet** window.

---

## How It Works

### High-level flow

```
User launches scanner.py
        │
        ▼
Tkinter window opens (NIGHTHAWK 2.0.0 dashboard)
        │
        ▼
User fills: Target · Ports · Scan type · Timing · Options
        │
        ▼
Click START SCAN
        │
        ▼
Target contains "/"?
   │                    │
  YES                   NO
   │                    │
   ▼                    ▼
Subnet sweep       Build Nmap command
(nmap -sn)              │
   │                    ▼
   ▼              Validate ports + flags
Checklist of            │
live hosts              ▼
   │              Launch background thread
   ▼                    │
User picks IPs          ▼
   │              subprocess.Popen(nmap -oX temp.xml)
   └──────────────►     │
                        ▼
                  Stream stdout → live log
                        │
                        ▼
                  Nmap exits (code 0)
                        │
                        ▼
                  Parse XML (ET.parse)
                        │
                        ▼
                  Build records[] list
                        │
                        ▼
                  Write .json .csv .txt .html
                        │
                        ▼
                  refresh_dashboard() — update all tabs
                        │
                        ▼
                  Auto-open HTML (optional)
```

### Scan execution pipeline

1. **`start_scan()`** — reads form values, validates target/ports/flags, and builds the Nmap command as a **list** (never a string — this prevents shell-injection).
2. **`_execute_command()`** — locks the UI (disables Start, enables Stop, starts spinner) and spawns a daemon thread.
3. **`run_scan()`** — runs `subprocess.Popen(nmap)` and reads stdout line-by-line. Every UI update goes through `root.after(0, …)` so Tkinter is only ever touched from the main thread.
4. **`create_reports()`** — parses Nmap's XML with `xml.etree.ElementTree`, flattens every `<host>` and `<ports/port>` into a plain Python dictionary, and detects which optional features the scan returned (OS info? scripts? versions?).
5. **`_finalize_reports()`** — writes the four report files, refreshes the dashboard tabs, unlocks the UI, and optionally opens the HTML report.
6. **`refresh_dashboard()`** — copies the parsed results into every Version 2 widget: summary cards, info rows, ports table, script output, and the risk gauge.

### Threading model

Tkinter is **not thread-safe** — a background thread must never call `widget.config()` directly. NIGHTHAWK solves this by marshalling every UI change through `root.after(0, callable, *args)`, which queues the callable and executes it on the main thread at the next idle moment. The worker thread only calls `subprocess.Popen`, reads stdout, and queues callables.

### Risk assessment

The same `_risk_assessment()` function drives both the desktop gauge and the HTML report badge:

| Severity | Triggered when… |
|---|---|
| **CRITICAL** (maroon) | Any script output contains `exploit`, `remote code execution`, or `critical` |
| **HIGH RISK** (red) | Any script output contains `vulnerable`, `cve-`, or `high severity` |
| **REVIEW** (orange) | Any script returned output at all |
| **EXPOSED** (yellow) | Any port is in the `open` state |
| **CLEAR** (green) | No open ports and no script findings |

---

## Requirements

| Component | Version | Notes |
|---|---|---|
| **Python** | 3.9 or newer | Must include Tkinter |
| **Tkinter** | Bundled with Python | On Linux, install `python3-tk` separately |
| **Nmap** | Any recent version | Must be available on `PATH` |
| **pip packages** | **None** | NIGHTHAWK uses only the Python standard library |

---

## Installation

### Linux — Kali / Debian / Ubuntu

```bash
# 1. Clone the repository
git clone https://github.com/r4tnadeepbose/NIGHTHAWK.git
cd NIGHTHAWK

# 2. Install system dependencies
sudo apt update
sudo apt install -y nmap python3 python3-tk

# 3. Check everything is present
./requirements.txt

# 4. Launch NIGHTHAWK
./scanner.py
```

Use **elevated privileges only for scan types that require raw packets** — TCP SYN (`-sS`), UDP (`-sU`), OS detection (`-O`), and most evasion modes:

```bash
sudo -E ./scanner.py
```

**Useful Make targets:**

```bash
make check       # verify Python, Tkinter, and Nmap are installed
make man         # preview the manual page (man ./nighthawk.1)
```

**System-wide install:**

```bash
sudo ./install.sh
nighthawk        # run from anywhere
```

### Windows

1. Download the [NIGHTHAWK ZIP](https://github.com/r4tnadeepbose/NIGHTHAWK/archive/refs/heads/main.zip) and extract it.
2. Install **Python 3.9+** from [python.org](https://www.python.org/downloads/) — tick **Add Python to PATH** during setup.
3. Install **Nmap** from [nmap.org](https://nmap.org/download.html) and make sure it's added to `PATH` during setup.
4. Open PowerShell in the extracted folder and run:

```powershell
cd "$HOME\Downloads\NIGHTHAWK-main"
py .\scanner.py
```

If the `py` launcher isn't available, use:

```powershell
python .\scanner.py
```

> **Windows note:** TCP SYN, UDP, and OS detection require Administrator privileges. Right-click PowerShell → **Run as administrator** before launching.

### macOS

```bash
brew install nmap python-tk
git clone https://github.com/r4tnadeepbose/NIGHTHAWK.git
cd NIGHTHAWK
python3 scanner.py
```

Raw-packet scans require `sudo`:

```bash
sudo python3 scanner.py
```

---

## Using NIGHTHAWK

### Basic scan

1. **Enter a target** in the left sidebar — a hostname (`scanme.nmap.org`), an IP address (`192.168.1.1`), or a CIDR range (`192.168.1.0/24`).
2. **Choose ports** — free-form (`22,80,443`, `1-1024`) or pick a preset (**Top 100**, **Top 1000**, **All**).
3. **Choose a scan type** — e.g. *TCP Connect (-sT)* for non-root, *TCP SYN (-sS)* for stealth.
4. **Choose timing** — `-T3` (Normal) is safe; `-T5` (Insane) is fast but noisy.
5. **Tick optional features** — Service detection, OS detection, NSE scripts.
6. Click **▶ START SCAN**.

### Watching the scan

- The **Live output** tab streams Nmap's stdout in real time — green lines are open ports, yellow are filtered, red are errors.
- The **MAC / OS** strip beneath the progress bar updates as Nmap learns more about the host.
- Summary cards flip from `—` to real counts as soon as the scan completes.

### Reviewing results

- **Overview** — target metadata + risk gauge.
- **Ports & Services** — sortable table with state, service, version, and reason.
- **Script output** — full NSE output per port.
- **Export** — buttons to open the HTML report or the JSON/CSV/TXT files.

### Subnet sweep

If the target contains a `/` (e.g. `192.168.1.0/24`), NIGHTHAWK first runs `nmap -sn <CIDR>` to discover live hosts, then shows a **checklist** so you can pick which ones to scan in depth. This is often the fastest way to map a home or lab network.

### Scan history & diff

Open **Reports → SCAN HISTORY & DIFF**:

- Every completed scan appears as a row (`date · target · ports · open-port count`).
- Ctrl-click **two rows**, then click **COMPARE SELECTED** — the right panel lists ports that were newly opened (`+`) or are no longer open (`-`).
- Double-click any row to open its HTML report in the browser.

### Presets

Click the **Profile** dropdown to load a pre-built configuration:

| Profile | What it does |
|---|---|
| **Quick TCP (Top 100)** | Fast `-sT` scan against the 100 most common ports, `-sV`, `-T5` |
| **Intense Scan (All)** | Full `-sT` scan against every port, `-sV -O -T4` |
| **Stealth SYN (Root)** | `-sS` on ports 1–1024, `-sV`, `-T1` (needs root) |
| **Evade Firewall** | Fragmented `-f` scan on ports 1–1024, `-sV`, `-T2` |
| **Ping Sweep** | `-sn` host discovery only, `-T3` |

To save the current form as your own preset, click **SAVE PRESET** in the sidebar.

---

## Reports

Every completed scan writes **four matching files** to `reports/`:

```
reports/nighthawk_YYYYMMDD_HHMMSS_<id>.{html,json,csv,txt}
```

| Format | Purpose |
|---|---|
| **`.html`** | Interactive dashboard report — summary cards, risk badge, port table with a live filter box, script output, JSON/CSV/TXT download buttons |
| **`.json`** | Machine-readable — the entire parsed scan as a single object |
| **`.csv`** | Spreadsheet-friendly — one row per port (formula-injection protected) |
| **`.txt`** | Plain text — one line per port, ideal for diffs or grep |

### What's inside the HTML report

- **Header** — logo, target, port range, timestamp, `SCAN COMPLETE` badge.
- **Summary cards** — hosts up · open ports · script findings · ports scanned.
- **Target information** — IP · MAC · OS · network distance.
- **Risk assessment** — the same Clear / Exposed / Review / High Risk / Critical badge shown in the app.
- **Ports & services table** — searchable by port, state, service, or version.
- **Script output** — every NSE finding, expandable.
- **Export buttons** — download the JSON, CSV, and TXT companions directly from the browser.

The HTML file is **fully standalone** — all CSS, JavaScript, and data are embedded, so you can email it, share it, or archive it without any external dependencies.

---

## Command-Line Usage

```bash
./scanner.py --help      # print usage information
./scanner.py --version   # print version
```

Example `--help` output:

```
NIGHTHAWK 2.0.0 - Advanced Network Scanner

Usage: ./scanner.py [OPTIONS]

Options:
  -h, --help       Show this help message and exit
  -V, --version    Show version information and exit

Requirements:
  Python 3.9 or newer with Tkinter, and Nmap on PATH.
  Run ./requirements.txt to check or install Linux prerequisites.

Reports:
  Completed scans are written to ./reports/ as HTML, JSON, CSV, and TXT files.

Only scan hosts you own or have permission to test.
```

---

## Project Structure

```
NIGHTHAWK/
│
├── scanner.py               ← the entire application (single file)
├── logo.png                 ← dashboard & report logo
├── nighthawk_config.json    ← saved user preferences (created on first run)
├── requirements.txt         ← dependency checker (executable)
├── install.sh               ← Linux system-wide installer
├── Makefile                 ← make check / make man
├── nighthawk.1              ← man page
├── README.md
├── HELP.md
│
├── .vscode/                 ← optional editor settings
│
└── reports/                 ← auto-created; holds all completed scans
    ├── nighthawk_20240115_143012_a1b2c3d4.html
    ├── nighthawk_20240115_143012_a1b2c3d4.json
    ├── nighthawk_20240115_143012_a1b2c3d4.csv
    └── nighthawk_20240115_143012_a1b2c3d4.txt
```

---

## Safety & Security Design

NIGHTHAWK is built to be safe by default — even though it wraps a powerful tool.

| Guard | What it protects against |
|---|---|
| **Blocked Nmap flags** | `-oN`, `-oX`, `-oG`, `-oA`, `-iL`, `-iR`, `--datadir`, `--stylesheet`, `--webxml`, `--resume`, `--append-output` — these could overwrite report files or read arbitrary data, so they are rejected |
| **Port validation** | Expressions are parsed, bounded to 1–65535, and length-limited before ever reaching Nmap |
| **List-form command building** | The Nmap command is a Python **list**, not a shell string — there is no `shell=True`, so shell injection is impossible |
| **CSV formula-injection guard** | Any cell beginning with `=`, `+`, `-`, or `@` is prefixed with a single quote |
| **HTML escaping** | Every user-controlled string is passed through `html.escape()` before it enters the HTML report |
| **Thread-safe UI** | All background-thread UI updates are marshalled through `root.after(0, …)` |
| **Temporary files** | Nmap's XML output goes to a `tempfile.mkstemp()` path and is deleted after parsing |
| **Config failure tolerance** | A corrupted `nighthawk_config.json` silently falls back to safe defaults |

---

## Troubleshooting

| Symptom | Fix |
|---|---|
| `Nmap not found. Install it and add it to PATH.` | Install Nmap from [nmap.org](https://nmap.org/download.html) or `apt install nmap`, then restart your terminal |
| `ModuleNotFoundError: No module named 'tkinter'` | `sudo apt install python3-tk` (Linux) — Tkinter is bundled on Windows/macOS |
| Scans return all `filtered` | Host firewall is blocking Nmap. Try `-Pn` and a lower timing (`-T2`) |
| SYN / UDP / OS detection returns nothing | You need root. Run `sudo -E ./scanner.py` |
| Report opens but is blank | Check that `reports/` isn't read-only; check the Live output for `[ERROR]` lines |
| UI freezes during scan | Should not happen — if it does, check that no custom code is touching widgets from the worker thread |
| `Permission denied` on `./scanner.py` | `chmod +x scanner.py` |

---

## Contributing

Contributions are welcome. For any significant change please open an **issue** first to discuss what you'd like to change.

```bash
# Fork → clone → branch
git checkout -b feature/my-feature

# Make your change, then:
python3 -m py_compile scanner.py   # quick syntax check
make check                          # verify environment

git commit -m "feat: describe your change"
git push origin feature/my-feature
```

Please keep the beginner-friendly comment style — every non-obvious block gets a plain-English comment explaining **what** it does and **why**.

---

## License

No license file is currently included. Add one — **MIT** is a good default for portfolio projects.

---

## Author

**Ratnadeep Bose**
- GitHub: [@r4tnadeepbose](https://github.com/r4tnadeepbose)
- Repository: [github.com/r4tnadeepbose/NIGHTHAWK](https://github.com/r4tnadeepbose/NIGHTHAWK)

---

> **Legal notice:** Nmap is a legitimate security tool used by professionals. However, scanning networks you don't own or lack explicit permission to test is **illegal** in most countries. NIGHTHAWK's authors accept no liability for misuse. Only scan hosts you own or have written authorization to test.
