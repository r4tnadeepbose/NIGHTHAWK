# NIGHTHAWK Help

## Synopsis

`NIGHTHAWK` is a Tkinter graphical front end for Nmap. It builds Nmap commands from the selected options, shows live output, and writes reports after a scan.

Only scan hosts you own or have permission to test.

## Requirements

- Python 3.9 or newer
- Tkinter (`python3-tk` on Kali/Debian)
- Nmap 7.x or newer, available as `nmap`
- A graphical desktop session with access to `DISPLAY`

Check the local environment with:

```bash
./requirements.txt
```

If packages are missing, run `sudo ./requirements.txt` on a supported system.

## Quick start

Run ordinary scans as your regular user:

```bash
./scanner.py
# or
./nighthawk
```

Use elevated privileges only for scan types that need raw packets. `sudo -E` preserves the graphical display environment:

```bash
sudo -E ./scanner.py
```

## Workflow

1. Start NIGHTHAWK and enter a hostname, IP address, CIDR range, or target list.
2. Select a scan type, ports, optional service/OS detection, and scripts.
3. Choose **LAUNCH** and read the live Nmap output.
4. Open or export the completed reports, or compare JSON reports in the scan history.

## Reports

Reports are written beneath `./reports/`, with a shared timestamp and scan identifier:

```text
./reports/nighthawk_YYYYMMDD_HHMMSS_<id>.{html,json,csv,txt}
```

## Privileges

| Scan type | Typical privilege requirement |
|---|---|
| TCP Connect (`-sT`) | Normal user |
| Ping discovery (`-sn`) | Normal user in most cases |
| TCP SYN (`-sS`) | Root / raw-packet privilege |
| UDP (`-sU`) | Root / raw-packet privilege recommended |
| FIN, Xmas, NULL, ACK, Window, Maimon | Root / raw-packet privilege |
| OS detection (`-O`) | Root / raw-packet privilege usually required |
| Fragmentation, decoys, bad checksum, idle scan | Root / raw-packet privilege |

## Troubleshooting

| Problem | Suggested fix |
|---|---|
| `nmap` not found | Install Nmap, then confirm with `nmap --version`. |
| `No module named tkinter` | Install `python3-tk`, then rerun `./requirements.txt`. |
| GUI does not open under `sudo` | Use `sudo -E ./scanner.py` from your graphical terminal. |
| A privileged scan fails | Relaunch with `sudo -E` if you are authorized to use that scan type. |
| No report appears | Wait for the scan to complete and confirm the working directory is writable. |

## Examples

```bash
./scanner.py --help
./scanner.py --version
./requirements.txt
sudo -E ./scanner.py
make check
make man
```

For an Nmap TCP connect scan of a host, choose **TCP Connect** and target `127.0.0.1`; for a privileged SYN scan, start NIGHTHAWK with `sudo -E` before choosing **TCP SYN**.
