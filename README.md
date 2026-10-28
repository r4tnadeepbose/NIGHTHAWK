# NIGHTHAWK

NIGHTHAWK is a Tkinter GUI for Nmap with live output and HTML, JSON, CSV, and text reports.

Only scan hosts you own or have permission to test.

## Requirements

- Python 3.9 or newer with Tkinter
- Nmap on your `PATH`
- No pip packages: NIGHTHAWK uses only the Python standard library

## Linux (Kali/Debian)

Clone the project, then install and check the required system packages:

```bash
git clone https://github.com/r4tnadeepbose/NIGHTHAWK.git
cd NIGHTHAWK
sudo apt update
sudo apt install -y nmap python3 python3-tk
./requirements.txt
```

Start ordinary scans as your regular user:

```bash
./scanner.py
```

Some Nmap scan types need raw-packet privileges. When you are authorized to use them, preserve the desktop display environment with:

```bash
sudo -E ./scanner.py
```

Optional Linux commands:

```bash
make check       # check Python, Tkinter, and Nmap
make man         # preview nighthawk.1
sudo ./install.sh
nighthawk        # after installation
```

## Windows

1. Install Python 3.9+ from [python.org](https://www.python.org/downloads/) and select **Add Python to PATH**.
2. Install Nmap from [nmap.org/download](https://nmap.org/download.html) and allow its installer to add Nmap to `PATH`.
3. Open PowerShell in the project folder and run:

```powershell
py .\scanner.py
```

If `py` is unavailable, use:

```powershell
python .\scanner.py
```

Verify Nmap if NIGHTHAWK cannot find it:

```powershell
nmap --version
```

## Use

1. Enter a hostname, IP address, or CIDR range.
2. Choose ports and a scan type.
3. Select **LAUNCH** and review the live Nmap output.
4. Open the generated report when the scan completes.

Reports are saved as:

```text
reports/nighthawk_YYYYMMDD_HHMMSS_<id>.{html,json,csv,txt}
```

## Help

```bash
./scanner.py --help
./scanner.py --version
```

**Author:** Ratnadeep Bose
