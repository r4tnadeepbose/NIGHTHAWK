#!/usr/bin/env python3
"""
NIGHTHAWK 2.0.0 — A beginner-friendly Tkinter front end for Nmap.

WHAT THIS PROGRAM DOES (in plain English):
1. It shows a desktop window (GUI) built with Tkinter.
2. The user picks a target (an IP address or a network range), ports to scan,
   a scan type, timing, and optional extra Nmap flags.
3. The program builds a safe Nmap command from those choices.
4. It runs Nmap in the background (so the window does not freeze).
5. It reads Nmap's XML result file.
6. It writes four report formats: HTML, JSON, CSV, and plain text.
7. It shows the results inside the app in tabs and can open the HTML report
   in a web browser.

SAFETY NOTES:
- Only scan hosts you own or have explicit permission to test.
- The program blocks certain dangerous Nmap flags (like -oN, -oX) so the
  user cannot accidentally overwrite NIGHTHAWK's own report files.
"""

# ---------------------------------------------------------------------------
# IMPORTS — Every import below is a tool the program needs.
# Think of imports as "bringing in a toolbox" before starting work.
# ---------------------------------------------------------------------------
import csv                      # For writing CSV (spreadsheet) report files.
import datetime                 # For timestamps like "2024-01-15 14:30:00".
import html                     # For safely escaping text placed inside HTML.
import json                     # For reading/writing JSON config and reports.
import os                       # For operating-system tasks (closing files, etc.).
import re                       # For "regular expressions" — pattern matching in text.
import shlex                    # For safely splitting command-line text into arguments.
import shutil                   # For finding programs (like Nmap) on the system PATH.
import subprocess               # For launching Nmap as a child process.
import sys                      # For reading command-line arguments (--help, --version).
import tempfile                 # For creating temporary files (Nmap XML output).
import threading                # For running scans in a background thread.
import tkinter as tk            # The main GUI toolkit for building the window.
import uuid                     # For generating unique IDs in report filenames.
import webbrowser               # For opening the HTML report in a browser.
import xml.etree.ElementTree as ET  # For parsing Nmap's XML output.
from pathlib import Path        # For handling file paths in a clean, modern way.
from tkinter import messagebox, scrolledtext, ttk, simpledialog
#   messagebox     → small pop-up dialogs (info, error, warning).
#   scrolledtext   → a text box with a scrollbar (used for logs and script output).
#   ttk            → themed widgets (progress bar, notebook tabs, treeview table).
#   simpledialog   → small dialog to ask the user for text input (e.g., preset name).


# ---------------------------------------------------------------------------
# MAIN CLASS — NighthawkApp
# This single class holds ALL application state and behavior.
# Think of it as the "brain" of the whole program.
# ---------------------------------------------------------------------------
class NighthawkApp:
    """Store the application state and all user-interface actions in one class."""

    # -----------------------------------------------------------------------
    # COLOR CONSTANTS — Named colors used everywhere in the UI.
    # Keeping colors in one place makes the whole dashboard look consistent.
    # -----------------------------------------------------------------------
    BG = "#000000"        # Main background (pure black).
    PANEL = "#171717"     # Panel background (very dark gray).
    FG = "#f5f7fa"        # Main foreground text (almost white).
    MUTED = "#a6adb8"     # Secondary/muted text (gray).
    ACCENT = "#3595F9"    # Accent/primary color (blue) — buttons, highlights.
    WARN = "#FEDD0B"      # Warning color (yellow).
    ERROR = "#E05263"     # Error color (red-pink).
    ORANGE = "#F2994A"    # "Review" risk color (orange).
    CRITICAL = "#7A1E30"  # Critical risk color (dark maroon).
    HEALTHY = "#27AE60"   # Healthy/safe color (green).

    # -----------------------------------------------------------------------
    # INPUT LIMITS — Maximum lengths allowed for user input.
    # These prevent abuse or accidental huge inputs.
    # -----------------------------------------------------------------------
    MAX_TARGET_LENGTH = 253             # Max length of a target string (DNS limit).
    MAX_PORT_EXPRESSION_LENGTH = 256    # Max length of a port expression like "1-1024".
    MAX_CUSTOM_FLAGS_LENGTH = 2048      # Max length of custom Nmap flags text.
    MAX_REPORT_XML_BYTES = 25 * 1024 * 1024  # Max size of XML file we accept (25 MB).

    # -----------------------------------------------------------------------
    # BLOCKED FLAGS — Nmap flags we refuse to pass through the "Custom flags"
    # or "Extra flags" fields. Why? Because some flags would let a user
    # overwrite NIGHTHAWK's own report files or read arbitrary files.
    # -----------------------------------------------------------------------
    BLOCKED_CUSTOM_FLAGS = {
        "-il", "-ir", "--datadir", "--stylesheet", "--webxml",
        "--resume", "--append-output", "-on", "-ox", "-og", "-oa",
    }

    # -----------------------------------------------------------------------
    # SCAN TYPES — A dictionary (key → value) of scan types the user can pick.
    # Each entry maps a friendly label to a tuple: (nmap_flag, explanation).
    # A value of (None, None) means "this is a separator line, not a real scan".
    # -----------------------------------------------------------------------
    SCAN_TYPES = {
        # --- Basic Scans ---------------------------------------------------
        "TCP Connect (-sT)": ("-sT", "Completes a TCP connection; works without admin."),
        "TCP SYN (-sS)": ("-sS", "Half-open TCP scan; usually requires admin."),
        "UDP Scan (-sU)": ("-sU", "Probes UDP services; slower, requires admin."),
        "FIN Scan (-sF)": ("-sF", "Sends FIN packets to bypass simple firewalls."),
        "Xmas Scan (-sX)": ("-sX", "Sends FIN, PSH, and URG flags."),
        "NULL Scan (-sN)": ("-sN", "Sends TCP packets without flags."),
        "ACK Scan (-sA)": ("-sA", "Maps firewall rules."),
        "Window Scan (-sW)": ("-sW", "TCP window scan."),
        "Maimon Scan (-sM)": ("-sM", "TCP Maimon scan."),

        # --- Discovery & Protocol -----------------------------------------
        "Ping Discovery (-sn)": ("-sn", "Discovers online hosts without port scanning."),
        "IP Protocol (-sO)": ("-sO", "Scans IP protocols instead of ports."),

        # --- Firewall / IDS Evasion ---------------------------------------
        "--- FIREWALL / IDS BYPASS ---": (None, None),  # Visual separator only.
        "Fragment Packets (-f)": ("-f", "Fragments packets to bypass simple firewalls."),
        "Custom MTU (--mtu 24)": ("--mtu 24", "Sets a specific packet size to confuse firewalls."),
        "Decoy Scan (-D RND:10)": ("-D RND:10", "Cloaks scan with 10 random decoys."),
        "Spoof MAC (--spoof-mac 0)": ("--spoof-mac 0", "Generates a random MAC address."),
        "Bad Checksum (--badsum)": ("--badsum", "Sends packets with bad checksums to identify firewalls."),
        "Idle Scan (-sI)": ("-sI", "Advanced blind scan using a zombie host."),
        "Source Port Spoof (-g 53)": ("-g 53", "Uses a specific source port (like DNS 53) to bypass rules."),

        # --- Custom --------------------------------------------------------
        "--- CUSTOM ---": (None, None),  # Visual separator only.
        "Custom Flags": (None, "Use your own scanner flags."),
    }

    # -----------------------------------------------------------------------
    # TIMING TEMPLATES — Nmap's -T0 through -T5 timing options.
    # Higher numbers are faster but noisier (easier to detect).
    # -----------------------------------------------------------------------
    TIMING_TEMPLATES = {
        "Insane (T5)": "-T5",
        "Aggressive (T4)": "-T4",
        "Normal (T3)": "-T3",
        "Polite (T2)": "-T2",
        "Sneaky (T1)": "-T1",
        "Paranoid (T0)": "-T0",
    }

    # -----------------------------------------------------------------------
    # PROFILES — Pre-built scan configurations the user can pick quickly.
    # Each profile is a dictionary with keys: type, ports, service, os, timing.
    # "Custom / Manual" has value None, meaning: don't change anything.
    # -----------------------------------------------------------------------
    PROFILES = {
        "Custom / Manual": None,
        "Quick TCP (Top 100)": {"type": "TCP Connect (-sT)", "ports": "Top 100", "service": True, "os": False, "timing": "Insane (T5)"},
        "Intense Scan (All)": {"type": "TCP Connect (-sT)", "ports": "All", "service": True, "os": True, "timing": "Aggressive (T4)"},
        "Stealth SYN (Root)": {"type": "TCP SYN (-sS)", "ports": "1-1024", "service": True, "os": False, "timing": "Sneaky (T1)"},
        "Evade Firewall": {"type": "Fragment Packets (-f)", "ports": "1-1024", "service": True, "os": False, "timing": "Polite (T2)"},
        "Ping Sweep": {"type": "Ping Discovery (-sn)", "ports": "N/A", "service": False, "os": False, "timing": "Normal (T3)"},
    }

    # -----------------------------------------------------------------------
    # CONFIG_FILE — Where saved user preferences are stored.
    # It sits next to this script file (same folder).
    # -----------------------------------------------------------------------
    CONFIG_FILE = Path(__file__).with_name("nighthawk_config.json")

    # -----------------------------------------------------------------------
    # __init__ — The "constructor". Runs once when the app starts.
    # It sets up state variables, loads saved settings, and builds the UI.
    # -----------------------------------------------------------------------
    def __init__(self, root):
        """Save the main Tkinter window, load saved choices, then build the screen."""
        self.root = root                                   # The main window.
        self.root.title("NIGHTHAWK // Advanced Network Scanner")
        self.root.geometry("1150x850")                     # Initial window size.
        self.root.minsize(1000, 750)                       # Smallest allowed size.
        self.root.configure(bg=self.BG)                    # Background color.

        # --- Runtime state flags -------------------------------------------
        self.is_scanning = False                            # True while a scan runs.
        self.scan_process = None                            # The Nmap subprocess handle.
        self.last_report = None                             # Path to the latest HTML report.
        self.current_xml_path = None                        # Path to the temporary XML file.
        self.live_host_info = {"mac": "Scanning...", "os": "Scanning..."}  # Live MAC/OS.

        self.config = self.load_config()                    # Load saved preferences.
        self.build_ui()                                     # Build the screen.

    # -----------------------------------------------------------------------
    # load_config — Read saved preferences from disk.
    # If the file is missing or broken, return an empty dictionary (safe default).
    # -----------------------------------------------------------------------
    def load_config(self):
        """Read saved user choices; return an empty dictionary if no valid file exists."""
        if self.CONFIG_FILE.exists():
            try:
                return json.loads(self.CONFIG_FILE.read_text(encoding="utf-8"))
            except Exception:
                pass  # If anything goes wrong, fall through to the default.
        return {}

    # -----------------------------------------------------------------------
    # save_config — Write the current preferences to disk as JSON.
    # Failures are silently ignored (saving is not critical).
    # -----------------------------------------------------------------------
    def save_config(self):
        """Save only small UI preferences so they are available next time the app opens."""
        try:
            self.CONFIG_FILE.write_text(json.dumps(self.config, indent=2), encoding="utf-8")
        except Exception:
            pass

    # =======================================================================
    # LEGACY VERSION 1 UI — Kept for reference only.
    # The "real" UI used at runtime is the Version 2 build_ui() at the bottom
    # of the class. Because Python uses the LAST definition of a method, the
    # Version 2 build_ui() overrides this one. Comments here explain the
    # original design for anyone studying the history.
    # =======================================================================
    def build_ui(self):
        """Build the active Version 2 dashboard: sidebar, summary cards, and report tabs."""
        """Legacy Version 1 layout kept below for reference; Version 2 overrides it later."""
        # --- HEADER: Logo, subtitle, cheatsheet button, auto-open toggle ---
        header = tk.Frame(self.root, bg=self.BG, padx=18, pady=14)
        header.pack(fill=tk.X)
        tk.Label(header, text="NIGHTHAWK", font=("Consolas", 24, "bold"),
                 fg=self.ACCENT, bg=self.BG).pack(side=tk.LEFT)
        tk.Label(header, text="  //  ADVANCED NETWORK RECON",
                 font=("Consolas", 10), fg=self.MUTED, bg=self.BG).pack(side=tk.LEFT, pady=(9, 0))

        # "CHEATSHEET" button opens a help window with common Nmap examples.
        tk.Button(header, text="? CHEATSHEET", command=self.show_cheatsheet,
                  bg=self.PANEL, fg=self.ACCENT, font=("Consolas", 9, "bold"),
                  relief=tk.FLAT, padx=10, cursor="hand2").pack(side=tk.RIGHT, padx=10)

        # "AUTO-OPEN" checkbox controls whether the HTML report opens automatically.
        self.auto_open_var = tk.BooleanVar(value=self.config.get("auto_open", True))
        self.option(header, "AUTO-OPEN", self.auto_open_var).pack(side=tk.RIGHT, padx=10)

        # --- CONFIG PANEL: Profile, target, ports, scan type, timing -----
        panel = tk.Frame(self.root, bg=self.PANEL, padx=14, pady=12)
        panel.pack(fill=tk.X, padx=14)

        # Profile drop-down (pre-built scan configurations).
        self.add_label(panel, "PROFILE").grid(row=0, column=0, sticky="w")
        self.profile_var = tk.StringVar(value=self.config.get("profile", "Custom / Manual"))
        self.profile_menu = tk.OptionMenu(panel, self.profile_var, *self.PROFILES, command=self.apply_profile)
        self.style_menu(self.profile_menu)
        self.profile_menu.grid(row=1, column=0, padx=(0, 12), sticky="ew")

        # Target text box (IP or CIDR).
        self.add_label(panel, "TARGET (IP or CIDR)").grid(row=0, column=1, sticky="w")
        self.target_entry = self.add_entry(panel, self.config.get("target", "127.0.0.1"), 25)
        self.target_entry.grid(row=1, column=1, padx=(0, 12), sticky="ew")

        # Ports text box plus a preset dropdown (Top 100 / All / Custom).
        self.add_label(panel, "PORTS").grid(row=0, column=2, sticky="w")
        port_frame = tk.Frame(panel, bg=self.PANEL)
        port_frame.grid(row=1, column=2, padx=(0, 12), sticky="ew")
        self.port_entry = self.add_entry(port_frame, self.config.get("ports", "1-1024"), 12)
        self.port_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.port_dropdown = tk.StringVar(value="Custom")
        port_menu = tk.OptionMenu(port_frame, self.port_dropdown, "Custom", "Top 100", "Top 1000", "All", command=self.apply_port_preset)
        self.style_menu(port_menu)
        port_menu.pack(side=tk.LEFT, padx=(5, 0))

        # Scan type drop-down. We manually inject separators because the
        # SCAN_TYPES dictionary contains "---" entries that are visual only.
        self.add_label(panel, "SCAN TYPE").grid(row=0, column=3, sticky="w")
        self.scan_type = tk.StringVar(value=self.config.get("scan_type", "TCP Connect (-sT)"))
        self.scan_menu = tk.OptionMenu(panel, self.scan_type, *self.SCAN_TYPES, command=self.scan_type_changed)
        self.style_menu(self.scan_menu)
        menu = self.scan_menu["menu"]
        menu.delete(0, "end")
        for key in self.SCAN_TYPES:
            if key.startswith("---"):
                menu.add_separator()  # Horizontal line instead of a clickable item.
            else:
                menu.add_command(label=key, command=lambda v=key: self._set_scan_type(v))
        self.scan_menu.grid(row=1, column=3, padx=(0, 12), sticky="ew")

        # Timing drop-down.
        self.add_label(panel, "TIMING").grid(row=0, column=4, sticky="w")
        self.timing_var = tk.StringVar(value=self.config.get("timing", "Insane (T5)"))
        self.timing_menu = tk.OptionMenu(panel, self.timing_var, *self.TIMING_TEMPLATES)
        self.style_menu(self.timing_menu)
        self.timing_menu.grid(row=1, column=4, padx=(0, 12), sticky="ew")

        # Column weights make the layout stretch nicely.
        panel.grid_columnconfigure(0, weight=1)
        panel.grid_columnconfigure(1, weight=3)
        panel.grid_columnconfigure(2, weight=2)
        panel.grid_columnconfigure(3, weight=2)
        panel.grid_columnconfigure(4, weight=2)

        # --- OPTIONS & NSE: checkboxes for service/OS/script detection ----
        self.options_frame = tk.Frame(self.root, bg=self.BG, padx=16, pady=10)
        self.options_frame.pack(fill=tk.X)

        self.service_var = tk.BooleanVar(value=self.config.get("service", True))
        self.option(self.options_frame, "SERVICE / VERSION", self.service_var).pack(side=tk.LEFT)

        self.os_var = tk.BooleanVar(value=self.config.get("os", False))
        self.option(self.options_frame, "OS DETECTION", self.os_var).pack(side=tk.LEFT, padx=14)

        self.add_label(self.options_frame, "NSE SCRIPTS").pack(side=tk.LEFT, padx=(10, 5))
        self.nse_default = tk.BooleanVar(value=False)
        self.option(self.options_frame, "Default", self.nse_default).pack(side=tk.LEFT)
        self.nse_vuln = tk.BooleanVar(value=False)
        self.option(self.options_frame, "Vuln", self.nse_vuln).pack(side=tk.LEFT)
        self.nse_http = tk.BooleanVar(value=False)
        self.option(self.options_frame, "HTTP-Enum", self.nse_http).pack(side=tk.LEFT)
        self.nse_ssl = tk.BooleanVar(value=False)
        self.option(self.options_frame, "SSL-Audit", self.nse_ssl).pack(side=tk.LEFT)

        # --- EXTRA FLAGS: free-form Nmap flags (e.g., --reason) -----------
        extra_frame = tk.Frame(self.root, bg=self.BG, padx=16, pady=0)
        extra_frame.pack(fill=tk.X)
        self.add_label(extra_frame, "EXTRA FLAGS").pack(side=tk.LEFT)
        self.extra_entry = self.add_entry(extra_frame, self.config.get("extra_flags", "--reason"), 40)
        self.extra_entry.pack(side=tk.LEFT, padx=6, fill=tk.X, expand=True)
        self.save_fav_btn = self.button(extra_frame, "SAVE PRESET", self.save_favorite, "#19364a", self.MUTED)
        self.save_fav_btn.pack(side=tk.LEFT, padx=(6, 0))

        # --- CUSTOM MODE: only shown when "Custom Flags" is selected -----
        self.custom_frame = tk.Frame(self.root, bg="#172b28", padx=16, pady=10)
        self.add_label(self.custom_frame, "CUSTOM COMMAND").pack(side=tk.LEFT)
        self.custom_entry = self.add_entry(self.custom_frame, "-sT -sV --reason", 55)
        self.custom_entry.pack(side=tk.LEFT, padx=8, fill=tk.X, expand=True)
        self.custom_frame.pack_forget()  # Hidden until needed.
        self.entries = {"TARGET": self.target_entry}

        # --- COMMAND PREVIEW: shows the exact command that will run ------
        command = tk.Frame(self.root, bg=self.BG, padx=16, pady=8)
        command.pack(fill=tk.X)
        self.add_label(command, "COMMAND RUN").pack(side=tk.LEFT)
        self.command_var = tk.StringVar(value="Waiting for scan configuration...")
        tk.Entry(command, textvariable=self.command_var, state="readonly",
                 readonlybackground="#05090c", fg=self.ACCENT, relief=tk.FLAT,
                 font=("Consolas", 9)).pack(side=tk.LEFT, padx=10, fill=tk.X, expand=True)

        # --- CONTROLS: Start, Stop, Progress bar, live MAC/OS label -----
        controls = tk.Frame(self.root, bg=self.BG, padx=14, pady=10)
        controls.pack(fill=tk.X)
        self.start_btn = self.button(controls, "▶  LAUNCH", self.start_scan, "#123b2b", self.ACCENT)
        self.start_btn.pack(side=tk.LEFT)
        self.stop_btn = self.button(controls, "■  ABORT", self.stop_scan, "#3b1b20", self.ERROR)
        self.stop_btn.config(state=tk.DISABLED)  # Disabled until a scan starts.
        self.stop_btn.pack(side=tk.LEFT, padx=8)

        # Progress bar styling (ttk theme = "clam" gives us more control).
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Nighthawk.Horizontal.TProgressbar",
                        troughcolor="#05090c", background=self.ACCENT,
                        bordercolor=self.BG, lightcolor=self.ACCENT, darkcolor=self.ACCENT)
        style.layout("Nighthawk.Horizontal.TProgressbar", [
            ('Horizontal.Progressbar.trough', {
                'children': [('Horizontal.Progressbar.pbar', {'side': 'left', 'sticky': 'ns'})],
                'sticky': 'nswe'
            })
        ])
        self.progress = ttk.Progressbar(controls, mode="indeterminate", length=150,
                                        style="Nighthawk.Horizontal.TProgressbar")
        self.progress.pack(side=tk.LEFT, padx=10)

        # Live MAC/OS info label — updated while scanning.
        self.live_info_label = tk.Label(controls, text="MAC: --- | OS: ---",
                                        fg=self.WARN, bg=self.BG, font=("Consolas", 9, "bold"))
        self.live_info_label.pack(side=tk.LEFT, padx=15)

        # Status label on the right (READY, RUNNING, COMPLETE, etc.).
        self.status_label = tk.Label(controls, text="READY", fg=self.MUTED, bg=self.BG, font=("Consolas", 10))
        self.status_label.pack(side=tk.RIGHT)

        # --- TERMINAL OUTPUT: scrolling log of Nmap's live output -------
        self.output = scrolledtext.ScrolledText(self.root, state=tk.DISABLED, bg="#05090c",
                                                fg=self.FG, insertbackground=self.ACCENT,
                                                font=("Consolas", 10), relief=tk.FLAT, padx=10, pady=10)
        self.output.pack(fill=tk.BOTH, expand=True, padx=16, pady=(4, 10))

        # Tags let us color certain lines (open = green, closed = red, errors = yellow).
        self.output.tag_config("open", foreground="#20e08a")
        self.output.tag_config("closed", foreground="#ff6b6b")
        self.output.tag_config("error", foreground="#ffcc66")

        # --- FOOTER REPORTS: open, history, and export buttons ----------
        reports = tk.Frame(self.root, bg=self.BG, padx=16, pady=4)
        reports.pack(fill=tk.X)
        self.open_report_btn = self.button(reports, "OPEN REPORT", self.open_report, "#19364a", self.ACCENT)
        self.open_report_btn.config(state=tk.DISABLED)
        self.open_report_btn.pack(side=tk.LEFT)
        self.history_btn = self.button(reports, "HISTORY & DIFF", self.show_history, "#19364a", self.FG)
        self.history_btn.pack(side=tk.LEFT, padx=6)
        for label, ext in (("JSON", "json"), ("CSV", "csv"), ("TXT", "txt")):
            button = self.button(reports, label, lambda e=ext: self.export_report(e), "#19364a", self.FG)
            button.pack(side=tk.LEFT, padx=6)

    # -----------------------------------------------------------------------
    # _set_scan_type — Programmatically update the scan type field.
    # Also calls scan_type_changed so any dependent UI refreshes.
    # -----------------------------------------------------------------------
    def _set_scan_type(self, value):
        """Update the selected scan type and refresh fields that depend on that choice."""
        self.scan_type.set(value)
        self.scan_type_changed(value)

    # -----------------------------------------------------------------------
    # show_cheatsheet — Open a new window with common Nmap examples.
    # The content is a plain multi-line string shown in a read-only text box.
    # -----------------------------------------------------------------------
    def show_cheatsheet(self):
        """Open a separate read-only window with common Nmap examples and flags."""
        win = tk.Toplevel(self.root)                # A new child window.
        win.title("Nmap Cheatsheet")
        win.geometry("900x700")
        win.configure(bg=self.BG)

        text = scrolledtext.ScrolledText(win, bg="#05090c", fg=self.FG, font=("Consolas", 10), padx=15, pady=15)
        text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # A long reference string — all the common Nmap options grouped by category.
        cheatsheet = """TARGET SPECIFICATION
=========================
nmap 192.168.1.1               Scan a single IP
nmap 192.168.1.1 192.168.1.2   Scan specific IPs
nmap 192.168.1.0/24            Scan a range
nmap scanme.nmap.org           Scan a domain
nmap 192.168.1.0/24 -v         Scan using CIDR notation
-iL <file>                     Scan targets from a file
-iR <num>                      Scan random hosts
--exclude <host>               Exclude specific hosts

SCAN TECHNIQUES
=========================
-sS                            TCP SYN port scan (Default)
-sT                            TCP connect port scan (Default without root)
-sU                            UDP port scan
-sA                            TCP ACK port scan
-sW                            TCP Window port scan
-sM                            TCP Maimon port scan

HOST DISCOVERY
=========================
-sL                            List targets only
-sn                            Disable port scanning (Host discovery)
-Pn                            Disable host discovery (Port scan only)
-PS <ports>                    TCP SYN discovery
-PA <ports>                    TCP ACK discovery
-PU <ports>                    UDP discovery
-PR                            ARP discovery (local network)
-n                             Never do DNS resolution

PORT SPECIFICATION
=========================
-p 21                          Port scan for port x
-p 21-100                      Port range
-p U:53,T:21-25                Scan multiple TCP and UDP ports
-p http,https                  Port scan by service name
-F                             Fast port scan (Top 100)
--top-ports 2000               Scan the top x ports
-p-                            Scan all ports (65535)

SERVICE AND VERSION DETECTION
=========================
-sV                            Attempts to determine the service version
-sV --version-intensity 9      Intensity level 0-9
--version-light                Enable light mode (faster)
--version-all                  Enable intense mode (slower)
-A                             Enables OS detection, version detection, script scanning, and traceroute

OS DETECTION
=========================
-O                             Remote OS detection
--osscan-limit                 Limit OS detection to promising targets
--osscan-guess                 Guess OS more aggressively
--max-os-tries <num>           Set maximum number of OS detection tries

TIMING AND PERFORMANCE
=========================
-T0                            Paranoid (Evades IDS)
-T1                            Sneaky (Evades IDS)
-T2                            Polite (Slows down to use less bandwidth)
-T3                            Normal (Default)
-T4                            Aggressive (Assumes fast/reliable network)
-T5                            Insane (Assumes extremely fast network)
--host-timeout <time>          Give up on target after this long
--min-rate <num>               Send packets no slower than <num> per second
--max-rate <num>               Send packets no faster than <num> per second

NSE SCRIPTS
=========================
-sC                            Scan with default NSE scripts
--script default               Scan with default NSE scripts
--script <script>              Scan with a single script
--script <wildcard>            Scan with a wildcard
--script <script1>,<script2>   Scan with two scripts
--script-args <args>           NSE script with arguments

FIREWALL / IDS EVASION
=========================
-f                             Fragment packets
--mtu <val>                    Specify custom offset size (multiple of 8)
-D <decoy1,decoy2>             Cloak scan with decoys
-S <IP>                        Spoof source IP address
-g <port>                      Use given source port number
--data-length <num>            Append random data to sent packets
--ttl <val>                    Set IP time-to-live field
--spoof-mac <mac>              Spoof your MAC address

OUTPUT
=========================
-oN <file>                     Normal output
-oX <file>                     XML output
-oG <file>                     Grepable output
-oA <basename>                 Output in three major formats
-v                             Increase verbosity level
-d                             Increase debugging level
--reason                       Display reason Nmap thinks port is in state
--open                         Show only open ports

MISCELLANEOUS
=========================
-6                             Enable IPv6 scanning
-h                             Nmap help screen

BYPASS FIREWALL / USEFUL COMMANDS
=========================
nmap --script firewall-bypass <target>
nmap -sV www.acunetix.ac.in
nmap -sV --script=vulners www.acunetix.ac.in
nmap 192.168.0.1 -v -dd
nmap --script ftp-anon 192.168.0.1 -p 21
nmap -sV --version-intensity 5 google.com -p 80
nmap -sV --script=banner 142.250.67.174
nmap -sV -Pn -p 80 --open -v -script http-enum 192.168.1.1
"""
        text.insert(tk.END, cheatsheet)
        text.config(state=tk.DISABLED)  # Read-only.

    # -----------------------------------------------------------------------
    # apply_profile — When the user picks a profile, fill the form with
    # that profile's pre-set values (scan type, timing, ports, checkboxes).
    # -----------------------------------------------------------------------
    def apply_profile(self, profile_name):
        """Fill the form with a built-in scan profile selected by the user."""
        profile = self.PROFILES.get(profile_name)
        if not profile:
            return  # "Custom / Manual" — don't change anything.
        self._set_scan_type(profile["type"])
        self.timing_var.set(profile["timing"])
        self.port_dropdown.set(profile["ports"])
        self.apply_port_preset(profile["ports"])
        self.service_var.set(profile["service"])
        self.os_var.set(profile["os"])

    # -----------------------------------------------------------------------
    # apply_port_preset — Translate a friendly preset ("Top 100") into the
    # actual Nmap expression ("--top-ports 100") placed in the port field.
    # -----------------------------------------------------------------------
    def apply_port_preset(self, preset):
        """Translate a friendly port preset into the port expression Nmap understands."""
        self.port_entry.delete(0, tk.END)
        if preset == "Top 100":
            self.port_entry.insert(0, "--top-ports 100")
        elif preset == "Top 1000":
            self.port_entry.insert(0, "--top-ports 1000")
        elif preset == "All":
            self.port_entry.insert(0, "1-65535")
        else:
            self.port_entry.insert(0, "1-1024")  # Default range.

    # -----------------------------------------------------------------------
    # save_favorite — Ask the user for a name and save the current form
    # values as a reusable preset inside the config file.
    # -----------------------------------------------------------------------
    def save_favorite(self):
        """Ask for a name and save the current form values as a reusable local preset."""
        name = simpledialog.askstring("Save Preset", "Enter a name for this scan preset:", parent=self.root)
        if not name:
            return  # User cancelled.

        # Ensure the "favorites" section exists in the config.
        if "favorites" not in self.config:
            self.config["favorites"] = {}

        # Store every field we need to restore the form later.
        self.config["favorites"][name] = {
            "target": self.target_entry.get(),
            "ports": self.port_entry.get(),
            "scan_type": self.scan_type.get(),
            "timing": self.timing_var.get(),
            "extra_flags": self.extra_entry.get(),
            "service": self.service_var.get(),
            "os": self.os_var.get()
        }
        self.save_config()

        # Add the favorite to the profile drop-down so it can be selected later.
        if name not in self.PROFILES:
            self.PROFILES[name] = "favorite"
            self.profile_menu["menu"].add_command(label=name, command=lambda v=name: self.profile_var.set(v) or self.apply_favorite(v))
        messagebox.showinfo("Saved", f"Preset '{name}' saved.")

    # -----------------------------------------------------------------------
    # apply_favorite — Restore one saved preset into the form.
    # -----------------------------------------------------------------------
    def apply_favorite(self, name):
        """Restore one locally saved preset into the scan form."""
        if "favorites" in self.config and name in self.config["favorites"]:
            fav = self.config["favorites"][name]
            self.target_entry.delete(0, tk.END)
            self.target_entry.insert(0, fav["target"])
            self.port_entry.delete(0, tk.END)
            self.port_entry.insert(0, fav["ports"])
            self._set_scan_type(fav["scan_type"])
            self.timing_var.set(fav["timing"])
            self.extra_entry.delete(0, tk.END)
            self.extra_entry.insert(0, fav["extra_flags"])
            self.service_var.set(fav["service"])
            self.os_var.set(fav["os"])

    # -----------------------------------------------------------------------
    # SMALL UI HELPER METHODS — These reduce repetition when building widgets.
    # -----------------------------------------------------------------------

    def add_label(self, parent, text):
        """Create a small form label using the Version 1 helper style."""
        frame = tk.Frame(parent, bg=parent.cget("bg"))
        tk.Label(frame, text=text, fg=self.MUTED, bg=parent.cget("bg"),
                 font=("Consolas", 8, "bold")).pack(side=tk.LEFT)
        return frame

    def add_entry(self, parent, value, width):
        """Create a single-line text box and prefill it with a value."""
        entry = tk.Entry(parent, width=width, bg="#192936", fg=self.FG,
                         insertbackground=self.ACCENT, relief=tk.FLAT, font=("Consolas", 10))
        entry.insert(0, value)
        return entry

    def option(self, parent, text, variable):
        """Create a check box tied to a Tkinter BooleanVar."""
        return tk.Checkbutton(parent, text=text, variable=variable, fg=self.FG, bg=parent.cget("bg"),
                               selectcolor=self.PANEL, activebackground=self.BG, activeforeground=self.ACCENT,
                               font=("Consolas", 9), relief=tk.FLAT)

    def style_menu(self, menu):
        """Apply the older menu colors to a Tkinter OptionMenu."""
        menu.config(bg="#192936", fg=self.FG, activebackground="#223d4c",
                    activeforeground=self.ACCENT, highlightthickness=0, width=24)
        menu["menu"].config(bg="#192936", fg=self.FG)

    def button(self, parent, text, command, background, foreground):
        """Create a consistently styled Version 1 button."""
        width = len(text) + 2
        return tk.Button(parent, text=text, command=command, bg=background, fg=foreground,
                         activebackground="#28536a", activeforeground="white",
                         font=("Consolas", 9, "bold"), relief=tk.FLAT,
                         width=width, padx=6, pady=7)

    # -----------------------------------------------------------------------
    # log — Append one line to the live output area, colored by keywords.
    # -----------------------------------------------------------------------
    def log(self, text):
        """Append one line to the live log and color it by simple status keywords."""
        self.output.config(state=tk.NORMAL)  # Must unlock before editing.
        if "open" in text.lower():
            self.output.insert(tk.END, text + "\n", ("open",))
        elif "closed" in text.lower() or "filtered" in text.lower():
            self.output.insert(tk.END, text + "\n", ("closed",))
        elif "error" in text.lower() or "fail" in text.lower():
            self.output.insert(tk.END, text + "\n", ("error",))
        else:
            self.output.insert(tk.END, text + "\n")
        self.output.see(tk.END)              # Auto-scroll to bottom.
        self.output.config(state=tk.DISABLED)  # Lock again.

    # -----------------------------------------------------------------------
    # update_live_info — Peek at one Nmap output line for MAC/OS details
    # and update the small live info label at the top of the controls.
    # -----------------------------------------------------------------------
    def update_live_info(self, text):
        """Look for MAC and OS details in one line of Nmap output and show them live."""
        mac_match = re.search(r"MAC Address: ([0-9A-F:]+) \(([^)]+)\)", text)
        if mac_match:
            self.live_host_info["mac"] = f"{mac_match.group(1)} ({mac_match.group(2)})"

        os_match = re.search(r"OS details: (.*)", text)
        if os_match:
            self.live_host_info["os"] = os_match.group(1)

        self.live_info_label.config(text=f"MAC: {self.live_host_info['mac']} | OS: {self.live_host_info['os']}")

    # -----------------------------------------------------------------------
    # update_ui — Safely schedule a UI update from a background thread.
    # Tkinter is NOT thread-safe, so any thread that wants to touch widgets
    # MUST ask the main thread to do it using root.after(0, ...).
    # -----------------------------------------------------------------------
    def update_ui(self, callback, *args, **kwargs):
        """Schedule a UI change safely from a background scan thread."""
        self.root.after(0, lambda: callback(*args, **kwargs))

    # -----------------------------------------------------------------------
    # scan_type_changed — Show or hide the custom/evasion UI elements
    # based on which scan type the user picked.
    # -----------------------------------------------------------------------
    def scan_type_changed(self, selected):
        """Legacy field visibility handler; Version 2 supplies the active handler later."""
        # These scan types need the "custom flags" box visible.
        custom_types = [
            "Custom Flags", "Fragment Packets (-f)", "Custom MTU (--mtu 24)",
            "Decoy Scan (-D RND:10)", "Spoof MAC (--spoof-mac 0)",
            "Bad Checksum (--badsum)", "Idle Scan (-sI)", "Source Port Spoof (-g 53)"
        ]

        if selected in custom_types:
            self.options_frame.pack_forget()  # Hide standard options.
            if selected == "Custom Flags":
                self.custom_frame.pack(fill=tk.X, before=self.output)
            else:
                self.custom_frame.pack_forget()
        else:
            self.custom_frame.pack_forget()
            self.options_frame.pack(fill=tk.X, before=self.output)

    # =======================================================================
    # START SCAN — The main "go" button.
    # Steps:
    # 1. Read + save form values.
    # 2. Validate target and ports.
    # 3. If target has "/" → run subnet sweep (discover live hosts first).
    # 4. Otherwise → build the Nmap command and run it.
    # =======================================================================
    def start_scan(self):
        """Validate the form, build an Nmap command, and start the background scan."""
        host = self.target_entry.get().strip()
        ports = self.port_entry.get().strip()
        engine = shutil.which("nmap")  # Find "nmap" on the system PATH.

        # Persist current form values so they're restored next time.
        self.config["target"] = host
        self.config["ports"] = ports
        self.config["scan_type"] = self.scan_type.get()
        self.config["timing"] = self.timing_var.get()
        self.config["service"] = self.service_var.get()
        self.config["os"] = self.os_var.get()
        self.config["extra_flags"] = self.extra_entry.get()
        self.config["auto_open"] = self.auto_open_var.get()
        self.save_config()

        # --- Validation ---------------------------------------------------
        if not host or not ports:
            messagebox.showerror("NIGHTHAWK", "Target and port expression are required.")
            return
        if engine is None:
            messagebox.showerror("NIGHTHAWK", "Nmap not found. Install it and add it to PATH.")
            return

        # If the target contains a "/" (CIDR like 192.168.1.0/24),
        # run a discovery sweep first, then ask the user what to scan.
        if "/" in host:
            self.run_subnet_sweep(host, engine)
            return

        # Port expression check (skip for "N/A" and --top-ports forms).
        if not self.valid_ports(ports) and ports != "N/A" and not ports.startswith("--top-ports"):
            messagebox.showerror("NIGHTHAWK", "Use ports like 443, 1-1024, 22,80,443, or --top-ports 100.")
            return

        # Parse the custom/extra flags safely.
        try:
            flags_text = self.custom_entry.get() if self.scan_type.get() == "Custom Flags" else self.extra_entry.get()
            flags = self.parse_flags(flags_text)
        except ValueError as error:
            messagebox.showerror("NIGHTHAWK", f"Invalid custom flags: {error}")
            return

        if self.scan_type.get() == "Custom Flags" and not flags:
            messagebox.showerror("NIGHTHAWK", "Enter custom scanner flags.")
            return

        # --- BUILD THE NMAP COMMAND --------------------------------------
        # We build it as a LIST (not a single string) for safety.
        command = [engine]  # Start with the Nmap executable path.
        if self.scan_type.get() == "Custom Flags":
            command.extend(flags)
        else:
            # Get the base flag (e.g., -sT, -f) for the chosen scan type.
            base_flag = self.SCAN_TYPES[self.scan_type.get()][0]
            if base_flag:
                command.append(base_flag)

            command.append(self.TIMING_TEMPLATES[self.timing_var.get()])

            # Some scan types are "evasion-only" — adding -sV or -O to them
            # could conflict, so we skip those extras for those modes.
            evasion_types = [
                "Fragment Packets (-f)", "Custom MTU (--mtu 24)",
                "Decoy Scan (-D RND:10)", "Spoof MAC (--spoof-mac 0)",
                "Bad Checksum (--badsum)", "Idle Scan (-sI)", "Source Port Spoof (-g 53)"
            ]

            if self.service_var.get() and self.scan_type.get() not in ("Ping Discovery (-sn)", "IP Protocol (-sO)") and self.scan_type.get() not in evasion_types:
                command.append("-sV")
            if self.os_var.get() and self.scan_type.get() not in ("Ping Discovery (-sn)", "IP Protocol (-sO)") and self.scan_type.get() not in evasion_types:
                command.append("-O")

            # NSE scripts (Nmap Scripting Engine).
            if self.nse_default.get(): command.append("-sC")
            if self.nse_vuln.get(): command.extend(["--script", "vuln"])
            if self.nse_http.get(): command.extend(["--script", "http-enum"])
            if self.nse_ssl.get(): command.extend(["--script", "ssl-enum-ciphers"])

            command.extend(flags)

        # Create a fresh temporary XML file so Nmap can write structured results.
        self.current_xml_path = Path(self.xml_path())

        # Add the ports argument.
        if ports != "N/A":
            if ports.startswith("--top-ports"):
                command.extend(ports.split())
            else:
                command.extend(["-p", ports])

        # Output XML path + the target — these must come last.
        command.extend(["-oX", str(self.current_xml_path), host])
        self._execute_command(command, host, ports)

    # -----------------------------------------------------------------------
    # _execute_command — Prep the UI for a scan and kick off the worker thread.
    # -----------------------------------------------------------------------
    def _execute_command(self, command, host, ports):
        """Prepare the interface for a scan, then launch the worker thread."""
        self.scan_started_at = datetime.datetime.now()  # For duration calculation.
        self.command_var.set(self.display_command(command))  # Show preview.
        self.clear_output()

        self.is_scanning = True
        self.live_host_info = {"mac": "Scanning...", "os": "Scanning..."}
        self.update_ui(self.live_info_label.config, text="MAC: --- | OS: ---")

        # Lock/unlock buttons and start the spinner.
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.progress.start(10)  # Animate the progress bar every 10ms.
        self.status_label.config(text="RUNNING // REPORT CAPTURE ACTIVE", fg=self.ACCENT)

        # Launch the actual scan in a daemon thread so the UI stays responsive.
        threading.Thread(target=self.run_scan, args=(command, host, ports), daemon=True).start()

    # -----------------------------------------------------------------------
    # run_subnet_sweep — When the target is a CIDR range, first do a
    # discovery ping sweep to find live hosts, then let the user pick.
    # -----------------------------------------------------------------------
    def run_subnet_sweep(self, subnet, engine):
        """Use Nmap host discovery on a CIDR range before offering found hosts to scan."""
        self.clear_output()
        self.is_scanning = True
        self.start_btn.config(state=tk.DISABLED)
        self.status_label.config(text="DISCOVERING HOSTS...", fg=self.WARN)
        self.progress.start(10)
        self.update_ui(self.log, f"[*] Running Ping Sweep on {subnet}...")

        def sweep():
            """Worker thread: run 'nmap -sn' and parse live IPs from the output."""
            command = [engine, "-sn", "-T4", subnet]
            try:
                # On Windows, CREATE_NO_WINDOW prevents a black console popup.
                flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
                proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, creationflags=flags)
                out, _ = proc.communicate()  # Wait for it to finish and capture output.

                # Extract IPs using a regex. "Nmap scan report for NAME (IP)".
                ips = re.findall(r"Nmap scan report for (?:[^\s]+\s)?\(?([0-9\.]+)\)?", out)
                if not ips:
                    self.update_ui(self.log, "[-] No live hosts found.")
                    self.update_ui(self.finish_scan, "NO HOSTS")
                    return

                self.update_ui(self.log, f"[+] Found {len(ips)} live hosts.")
                self.update_ui(self.show_subnet_results, ips)
            except Exception as e:
                self.update_ui(self.log, f"[ERROR] {e}")
                self.update_ui(self.finish_scan, "ERROR")

        threading.Thread(target=sweep, daemon=True).start()

    # -----------------------------------------------------------------------
    # show_subnet_results — Pop up a checklist of live hosts and let the
    # user pick which ones to scan, then re-enter start_scan().
    # -----------------------------------------------------------------------
    def show_subnet_results(self, ips):
        """Show discovered IP addresses and let the user choose which ones to scan next."""
        self.finish_scan("READY")
        win = tk.Toplevel(self.root)
        win.title("Live Hosts Found")
        win.geometry("400x500")
        win.configure(bg=self.BG)

        tk.Label(win, text="Select targets to scan:", bg=self.BG, fg=self.ACCENT, font=("Consolas", 10, "bold")).pack(pady=10)

        frame = tk.Frame(win, bg=self.BG)
        frame.pack(fill=tk.BOTH, expand=True, padx=20)

        # One checkbox per discovered IP, all checked by default.
        vars = []
        for ip in ips:
            var = tk.BooleanVar(value=True)
            chk = tk.Checkbutton(frame, text=ip, variable=var, fg=self.FG, bg=self.BG, selectcolor=self.PANEL, font=("Consolas", 10))
            chk.pack(anchor="w")
            vars.append((ip, var))

        def scan_selected():
            """Collect checked IPs, join them with commas, and start a scan."""
            selected = [ip for ip, var in vars if var.get()]
            if not selected:
                messagebox.showwarning("Empty", "Select at least one host.")
                return
            win.destroy()
            self.target_entry.delete(0, tk.END)
            self.target_entry.insert(0, ",".join(selected))
            self.start_scan()

        tk.Button(win, text="SCAN SELECTED", command=scan_selected, bg="#19364a", fg=self.ACCENT, font=("Consolas", 10, "bold"), pady=5).pack(fill=tk.X, padx=20, pady=10)

    # -----------------------------------------------------------------------
    # valid_ports — Validate a port expression like "1-1024" or "22,80,443".
    # Rejects anything that isn't a well-formed, in-range expression.
    # -----------------------------------------------------------------------
    @staticmethod
    def valid_ports(expression):
        """Accept only simple, bounded port lists and ranges before passing them to Nmap."""
        if not expression:
            return False
        if expression.startswith("--top-ports"):
            return True
        if len(expression) > NighthawkApp.MAX_PORT_EXPRESSION_LENGTH:
            return False
        try:
            for part in expression.split(","):
                part = part.strip()
                if not part:
                    return False
                if "-" in part:
                    start, end = (int(value) for value in part.split("-", 1))
                    if not 1 <= start <= end <= 65535:
                        return False
                elif not 1 <= int(part) <= 65535:
                    return False
            return bool(expression)
        except ValueError:
            return False

    # -----------------------------------------------------------------------
    # parse_flags — Split "extra flags" text into a safe list of arguments.
    # Also blocks dangerous flags like -oX (which could overwrite our files).
    # -----------------------------------------------------------------------
    @classmethod
    def parse_flags(cls, text):
        """Split extra flags safely and block flags that could overwrite NIGHTHAWK files."""
        if len(text) > cls.MAX_CUSTOM_FLAGS_LENGTH:
            raise ValueError("custom flags are too long")
        flags = shlex.split(text, posix=False)  # Safe split respecting quotes.
        for flag in flags:
            option = flag.split("=", 1)[0].casefold()  # Normalize case.
            if option in cls.BLOCKED_CUSTOM_FLAGS or option.startswith(("-on", "-ox", "-og", "-oa", "-il", "-ir")):
                raise ValueError(f"{flag} is reserved.")
        return flags

    # -----------------------------------------------------------------------
    # xml_path — Return a brand-new temporary filename ending in ".xml".
    # Nmap will write its XML results there; we parse it and delete it later.
    # -----------------------------------------------------------------------
    def xml_path(self):
        """Create an empty temporary filename for Nmap's XML output."""
        handle, path = tempfile.mkstemp(suffix=".xml", prefix="nighthawk_")
        os.close(handle)  # We only want the path, not an open file handle.
        return path

    # -----------------------------------------------------------------------
    # run_scan — Runs in a background thread. Launches Nmap, streams its
    # stdout line-by-line into the log, waits for exit, then triggers report
    # creation (or cleans up on failure/abort).
    # -----------------------------------------------------------------------
    def run_scan(self, command, host, ports):
        """Run Nmap off the UI thread, stream its output, and request report creation."""
        self.update_ui(self.log, "$ " + self.display_command(command))
        try:
            flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
            self.scan_process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,   # Merge errors into stdout.
                text=True,
                encoding="utf-8",
                errors="replace",           # Never crash on bad bytes.
                creationflags=flags
            )
            # Read one line at a time so we can update the UI in real time.
            for line in self.scan_process.stdout:
                if not self.is_scanning:
                    continue  # User pressed Stop; discard remaining output.
                stripped = line.strip()

                # Quick-scrape MAC/OS info from any line we see.
                self.update_ui(self.update_live_info, line)

                # Suppress Nmap's noisy standard header/footer lines.
                if (stripped.startswith("Starting Nmap")
                        or stripped.startswith("Nmap done")
                        or stripped.startswith("Nmap scan report for")):
                    continue
                self.update_ui(self.log, line.rstrip())

            code = self.scan_process.wait()  # 0 = success, non-zero = problem.
        except OSError as error:
            self.update_ui(self.log, f"[ERROR] Could not start scanner: {error}")
            code = 1
        self.scan_process = None

        # Decide what to do based on exit code and whether the user aborted.
        if self.is_scanning and code == 0:
            self.update_ui(self.create_reports, host, ports)
        elif self.is_scanning:
            # Scan failed; clean up the temp file.
            if self.current_xml_path is not None:
                self.current_xml_path.unlink(missing_ok=True)
            self.update_ui(self.finish_scan, f"EXIT CODE {code}")
        elif self.current_xml_path is not None:
            # User aborted; clean up the temp file.
            self.current_xml_path.unlink(missing_ok=True)

    # -----------------------------------------------------------------------
    # create_reports — Parse the XML Nmap wrote and turn it into simple
    # Python dictionaries that are passed to _finalize_reports().
    # Also detects "feature flags" (did the scan return OS info? scripts?
    # versions?) so the reports can include those columns only when relevant.
    # -----------------------------------------------------------------------
    def create_reports(self, host, ports):
        """Parse Nmap XML into simple Python dictionaries used by every report format."""
        try:
            if self.current_xml_path is None:
                raise OSError("No report data path was created")
            xml_file = self.current_xml_path
            root = ET.parse(xml_file).getroot()  # The XML root element <nmaprun>.
            records = []

            # "Feature flags" — used later to decide which report columns to show.
            has_os_info = False
            has_mac_info = False
            has_uptime = False
            has_distance = False
            has_service_info = False
            has_version = False
            has_scripts = False

            # Host metadata (filled from XML as we find it).
            host_info = {
                "os": "Unknown", "mac": "Unknown", "vendor": "Unknown",
                "device": "Unknown", "uptime": "Unknown", "distance": "Unknown", "service_info": "Unknown"
            }

            # Loop over every <host> element in the XML.
            for host_node in root.findall("host"):
                # MAC address info.
                for address in host_node.findall("address"):
                    if address.get("addrtype") == "mac":
                        host_info["mac"] = address.get("addr", "Unknown")
                        host_info["vendor"] = address.get("vendor", "Unknown")
                        has_mac_info = True

                # Operating system match (best guess).
                os_node = host_node.find("os")
                if os_node is not None:
                    os_match = os_node.find("osmatch")
                    if os_match is not None:
                        host_info["os"] = os_match.get("name", "Unknown")
                        os_class = os_match.find("osclass")
                        if os_class is not None:
                            host_info["device"] = os_class.get("type", "Unknown")
                        has_os_info = True

                # Uptime (how long the host has been up).
                uptime_node = host_node.find("uptime")
                if uptime_node is not None:
                    host_info["uptime"] = f"{uptime_node.get('seconds')}s"
                    has_uptime = True

                # Network distance (how many hops away).
                distance_node = host_node.find("distance")
                if distance_node is not None:
                    host_info["distance"] = f"{distance_node.get('value')} hops"
                    has_distance = True

                # Host-level NSE scripts (e.g., smb-os-discovery).
                hostscript = host_node.find("hostscript")
                if hostscript is not None:
                    for script in hostscript.findall("script"):
                        if script.get("id") == "smb-os-discovery":
                            host_info["service_info"] = script.get("output", "").replace("\n", " | ")
                            has_service_info = True

                # Each scanned port.
                for port_node in host_node.findall("./ports/port"):
                    state = port_node.find("state")
                    if state is None:
                        continue  # Skip malformed entries.
                    service = port_node.find("service")

                    # Port-level NSE scripts.
                    script_output = []
                    for script in port_node.findall("script"):
                        script_id = script.get("id", "unknown")
                        output = script.get("output", "")
                        script_output.append({"id": script_id, "output": output})
                        has_scripts = True

                    if service is not None and (service.get("version") or service.get("product")):
                        has_version = True

                    # Store one flat dictionary per port for easy export.
                    records.append({
                        "host": host,
                        "protocol": port_node.get("protocol", ""),
                        "port": int(port_node.get("portid", 0)),
                        "state": state.get("state", ""),
                        "reason": state.get("reason", ""),
                        "service": service.get("name", "") if service is not None else "",
                        "version": service.get("version", "") if service is not None else "",
                        "product": service.get("product", "") if service is not None else "",
                        "extrainfo": service.get("extrainfo", "") if service is not None else "",
                        "scripts": script_output
                    })

            self._finalize_reports(records, host, ports, host_info, {
                "os": has_os_info, "mac": has_mac_info, "uptime": has_uptime,
                "distance": has_distance, "service_info": has_service_info,
                "version": has_version, "scripts": has_scripts
            })
        except Exception as e:
            self.update_ui(self.log, f"[ERROR] Could not parse scan data: {e}")
            self.update_ui(self.finish_scan, "REPORT ERROR")

    # -----------------------------------------------------------------------
    # _finalize_reports — Write all four report files after parsing succeeds.
    # Four formats are produced:
    #   .json — the raw data as machine-readable JSON.
    #   .csv  — spreadsheet-friendly table (with formula-injection protection).
    #   .txt  — plain text one-liner per port.
    #   .html — the fancy dashboard-style report.
    # -----------------------------------------------------------------------
    def _finalize_reports(self, records, host, ports, host_info, features):
        """Write all report files after XML parsing has finished successfully."""
        try:
            folder = Path(__file__).with_name("reports")   # ./reports/
            folder.mkdir(exist_ok=True)                    # Create it if needed.
            stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            base = folder / f"nighthawk_{stamp}_{uuid.uuid4().hex[:8]}"  # Base filename.

            # --- JSON report --------------------------------------------------
            data = {"target": host, "ports": ports, "info": host_info, "created": datetime.datetime.now().isoformat(), "results": records}
            self.last_scan_data = data  # Keep for future use.
            base.with_suffix(".json").write_text(json.dumps(data, indent=2), encoding="utf-8")

            # --- CSV report ---------------------------------------------------
            # Only include version columns if the scan returned them.
            csv_fields = ["host", "protocol", "port", "state", "reason", "service"]
            if features["version"]:
                csv_fields.extend(["version", "product", "extrainfo"])

            with base.with_suffix(".csv").open("w", newline="", encoding="utf-8") as file:
                writer = csv.DictWriter(file, fieldnames=csv_fields, extrasaction='ignore')
                writer.writeheader()
                # safe_csv_value prevents spreadsheet formula injection.
                writer.writerows({k: self.safe_csv_value(v) for k, v in row.items() if k in csv_fields} for row in records)

            # --- TXT report ---------------------------------------------------
            txt_content = "\n".join(
                f"{r['host']}:{r['port']}/{r['protocol']} {r['state']} {r['reason']} {r['service']} {r['version']}"
                for r in records
            )
            base.with_suffix(".txt").write_text(txt_content, encoding="utf-8")

            # --- HTML report (the visual dashboard) ---------------------------
            # Building the HTML table rows dynamically.
            rows = ""
            for r in records:
                version_str = f"{r['product']} {r['version']} {r['extrainfo']}".strip() if features["version"] else ""

                # Build the NSE script output block for this row (if any).
                script_html = ""
                if features["scripts"] and r["scripts"]:
                    script_html = "<div class='scripts-container'>"
                    for s in r["scripts"]:
                        formatted_out = html.escape(s["output"]).replace("\n", "<br>")
                        script_html += f"<div class='script-box'><strong>[{s['id']}]</strong><br>{formatted_out}</div>"
                    script_html += "</div>"

                row_html = f"<tr><td>{html.escape(str(r['host']))}</td><td>{r['protocol']}</td><td>{r['port']}</td><td>{r['state']}</td><td>{r['reason']}</td><td>{html.escape(r['service'])}</td>"
                if features["version"]:
                    row_html += f"<td>{html.escape(version_str)}</td>"
                if features["scripts"]:
                    row_html += f"<td>{script_html}</td>"
                row_html += "</tr>"
                rows += row_html

            # Table header row.
            thead = "<tr><th>Host</th><th>Protocol</th><th>Port</th><th>State</th><th>Reason</th><th>Service</th>"
            if features["version"]:
                thead += "<th>Version</th>"
            if features["scripts"]:
                thead += "<th>NSE Output</th>"
            thead += "</tr>"

            # Top metadata box (OS, MAC, uptime, etc.).
            info_html = ""
            if features["os"]:
                info_html += f"<div><strong>OS:</strong> {html.escape(host_info['os'])}</div>"
            if features["mac"]:
                info_html += f"<div><strong>MAC:</strong> {html.escape(host_info['mac'])}</div>"
            if features["uptime"]:
                info_html += f"<div><strong>Uptime:</strong> {html.escape(host_info['uptime'])}</div>"
            if features["distance"]:
                info_html += f"<div><strong>Distance:</strong> {html.escape(host_info['distance'])}</div>"
            if features["service_info"]:
                info_html += f"<div style='grid-column: span 2;'><strong>Service Info:</strong> {html.escape(host_info['service_info'])}</div>"

            info_box = ""
            if info_html:
                info_box = f'<div class="info-box"><div class="info-grid">{info_html}</div></div>'

            # NOTE: the `page` template built here is actually NOT used.
            # The very next line replaces it with a call to _dashboard_report_page().
            # This is a leftover from the Version 1 report format.
            page = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>NIGHTHAWK Report</title>
<style>
body {{ background:#091017; color:#b8f7d4; font:15px Consolas,monospace; padding:30px }}
h1 {{ color:#20e08a; margin-bottom: 5px; }}
.info-box {{ background:#111e29; border:1px solid #28536a; padding:15px; margin-bottom:20px; border-radius:5px; }}
.info-grid {{ display:grid; grid-template-columns: 1fr 1fr; gap:10px; }}
.controls {{ margin: 20px 0; display: flex; gap: 10px; flex-wrap: wrap; }}
input {{ background:#111e29; border:1px solid #28536a; color:#b8f7d4; padding:10px; width: min(520px, 100%); flex-grow: 1; }}
button {{ background:#19364a; color:#20e08a; border:none; padding:10px 20px; font-family:Consolas,monospace; font-weight:bold; cursor:pointer; transition: 0.2s; }}
button:hover {{ background:#28536a; }}
table {{ border-collapse:collapse; width:100%; margin-top:10px; }}
td,th {{ border:1px solid #28536a; padding:8px; text-align:left; vertical-align: top; }}
th {{ color:#20e08a; }}
tr:nth-child(even) {{ background:#111e29 }}

.scripts-container {{ max-height: 200px; overflow-y: auto; background: #05090c; padding: 10px; border-radius: 4px; font-size: 12px; }}
.script-box {{ margin-bottom: 15px; padding-bottom: 10px; border-bottom: 1px dashed #28536a; }}
.script-box strong {{ color: #ffcc66; }}
</style>
</head>
<body>
<h1>NIGHTHAWK // Scan Report</h1>
<p>Target: {html.escape(host)} | Ports: {html.escape(ports)}</p>

{info_box}

<div class="controls">
  <button onclick="downloadFile('json')">EXPORT JSON</button>
  <button onclick="downloadFile('csv')">EXPORT CSV</button>
  <button onclick="downloadFile('txt')">EXPORT TXT</button>
  <input id="filter" type="search" placeholder="Filter host, port, state, or service...">
</div>

<table id="results">
<thead>{thead}</thead>
<tbody>{rows}</tbody>
</table>

<script>
const reportData = {{
  json: {json.dumps(data)},
  csv: {json.dumps(base.with_suffix(".csv").read_text(encoding="utf-8"))},
  txt: {json.dumps(txt_content)}
}};

function downloadFile(ext) {{
  const blob = new Blob([reportData[ext]], {{ type: 'text/plain' }});
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = '{base.name}.' + ext;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}}

document.getElementById("filter").addEventListener("input", function () {{
  const query = this.value.toLowerCase();
  document.querySelectorAll("#results tbody tr").forEach(function (row) {{
    row.hidden = !row.textContent.toLowerCase().includes(query);
  }});
}});
</script>
</body>
</html>"""

            # ACTUALLY build the report using the Version 2 dashboard renderer.
            page = self._dashboard_report_page(data, base)
            base.with_suffix(".html").write_text(page, encoding="utf-8")
            self.last_report = base.with_suffix(".html")

            # Clean up the temp XML file.
            if self.current_xml_path is not None:
                self.current_xml_path.unlink(missing_ok=True)

            self.update_ui(self.log, f"[+] Reports saved: {base}.html / .json / .csv / .txt")
            self.update_ui(self.refresh_dashboard, data)  # Fill the dashboard tabs.
            self.update_ui(self.finish_scan, "COMPLETE")

            # Optionally open the HTML report in the browser.
            if self.auto_open_var.get():
                webbrowser.open(self.last_report.as_uri())

        except (OSError, ValueError) as error:
            self.update_ui(self.log, f"[ERROR] Could not create report: {error}")
            self.update_ui(self.finish_scan, "REPORT ERROR")

    # =======================================================================
    # LEGACY HISTORY DIALOG — kept for reference; the Version 2 override at
    # the bottom of the class takes precedence. See the Version 2 history
    # method for the active implementation.
    # =======================================================================
    def show_history(self):
        """Legacy history dialog; the Version 2 comparison workspace overrides it later."""
        folder = Path(__file__).with_name("reports")
        if not folder.exists():
            messagebox.showinfo("History", "No scans have been run yet.")
            return

        files = sorted(folder.glob("*.json"), reverse=True)  # Newest first.
        if not files:
            messagebox.showinfo("History", "No scans found in the reports folder.")
            return

        win = tk.Toplevel(self.root)
        win.title("Scan History & Diff Engine")
        win.geometry("850x550")
        win.configure(bg=self.BG)

        # Left panel = list of past scans. Right panel = diff output.
        left_frame = tk.Frame(win, bg=self.BG)
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=10, pady=10)

        right_frame = tk.Frame(win, bg=self.BG)
        right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=10, pady=10)

        tk.Label(left_frame, text="SELECT 2 SCANS TO COMPARE", bg=self.BG, fg=self.ACCENT, font=("Consolas", 9, "bold")).pack(anchor="w")
        self.listbox = tk.Listbox(left_frame, bg="#05090c", fg=self.FG, font=("Consolas", 10), relief=tk.FLAT, selectbackground="#19364a", exportselection=False)
        self.listbox.pack(fill=tk.BOTH, expand=True, pady=5)

        # Populate list with "date | target | ports".
        for f in files:
            try:
                data = json.loads(f.read_text(encoding="utf-8"))
                date = data.get("created", "")[:16].replace("T", " ")
                self.listbox.insert(tk.END, f"{date} | {data.get('target')} | {data.get('ports')}")
            except:
                self.listbox.insert(tk.END, f.name)

        def open_selected(event):
            """Double-click a row to open that scan's HTML report."""
            selection = self.listbox.curselection()
            if selection:
                idx = selection[0]
                target_html = files[idx].with_suffix(".html")
                if target_html.exists():
                    webbrowser.open(target_html.as_uri())

        self.listbox.bind("<Double-Button-1>", open_selected)

        tk.Label(right_frame, text="DIFF RESULTS", bg=self.BG, fg=self.ACCENT, font=("Consolas", 9, "bold")).pack(anchor="w")
        self.diff_text = scrolledtext.ScrolledText(right_frame, bg="#05090c", fg=self.FG, font=("Consolas", 10), relief=tk.FLAT)
        self.diff_text.pack(fill=tk.BOTH, expand=True, pady=5)

        btn_frame = tk.Frame(win, bg=self.BG)
        btn_frame.pack(fill=tk.X, side=tk.BOTTOM, padx=10, pady=10)

        def run_diff():
            """Compare the two selected scans and show added/removed open ports."""
            selections = self.listbox.curselection()
            if len(selections) != 2:
                messagebox.showwarning("Compare", "Please select exactly 2 scans (hold Ctrl to select multiple).")
                return

            file1 = files[selections[0]]
            file2 = files[selections[1]]

            try:
                data1 = json.loads(file1.read_text(encoding="utf-8"))
                data2 = json.loads(file2.read_text(encoding="utf-8"))

                # Build dictionaries keyed by port number, filtered to open-only.
                ports1 = {r["port"]: r for r in data1.get("results", []) if r["state"] == "open"}
                ports2 = {r["port"]: r for r in data2.get("results", []) if r["state"] == "open"}

                self.diff_text.config(state=tk.NORMAL)
                self.diff_text.delete(1.0, tk.END)
                self.diff_text.insert(tk.END, f"Comparing:\nOld: {file1.name}\nNew: {file2.name}\n\n")

                # Ports that are open in the new scan but not the old one.
                new_ports = set(ports2.keys()) - set(ports1.keys())
                if new_ports:
                    self.diff_text.insert(tk.END, "[!] NEWLY OPENED PORTS:\n", ("error",))
                    for p in new_ports:
                        self.diff_text.insert(tk.END, f"  + Port {p} ({ports2[p]['service']})\n", ("open",))

                # Ports that were open before but are gone now.
                closed_ports = set(ports1.keys()) - set(ports2.keys())
                if closed_ports:
                    self.diff_text.insert(tk.END, "[!] CLOSED PORTS:\n", ("error",))
                    for p in closed_ports:
                        self.diff_text.insert(tk.END, f"  - Port {p} ({ports1[p]['service']})\n", ("closed",))

                if not new_ports and not closed_ports:
                    self.diff_text.insert(tk.END, "No port differences found.\n", ("warn",))

                self.diff_text.config(state=tk.DISABLED)
            except Exception as e:
                messagebox.showerror("Error", str(e))

        tk.Button(btn_frame, text="COMPARE SELECTED", command=run_diff, bg="#19364a", fg=self.ACCENT, font=("Consolas", 9, "bold"), relief=tk.FLAT, padx=15, pady=5).pack(side=tk.RIGHT)

    # -----------------------------------------------------------------------
    # safe_csv_value — Prevent CSV injection attacks.
    # If a cell starts with = + - @, a spreadsheet might try to run it as a
    # formula. We prefix with a single quote to neutralize it.
    # -----------------------------------------------------------------------
    @staticmethod
    def safe_csv_value(value):
        """Prefix spreadsheet formula-like cells to prevent CSV formula execution."""
        text = str(value)
        if text.startswith(("=", "+", "-", "@")):
            return "'" + text
        return text

    # -----------------------------------------------------------------------
    # display_command — Format the command for display purposes.
    # We hide the actual Nmap exe path and replace it with "NIGHTHAWK" for
    # a cleaner preview and to avoid exposing local filesystem structure.
    # -----------------------------------------------------------------------
    def display_command(self, command):
        """Show a readable command preview without exposing the local Nmap executable path."""
        display_cmd = ["NIGHTHAWK", *command[1:]]
        return subprocess.list2cmdline(display_cmd)

    # -----------------------------------------------------------------------
    # clear_output — Wipe the live-output text box before a new scan starts.
    # -----------------------------------------------------------------------
    def clear_output(self):
        """Remove old lines from the live-output text area before a new scan starts."""
        self.output.config(state=tk.NORMAL)
        self.output.delete("1.0", tk.END)
        self.output.config(state=tk.DISABLED)

    # -----------------------------------------------------------------------
    # stop_scan — Handle the "STOP" button. Ask Nmap to terminate and
    # reset the UI to idle.
    # -----------------------------------------------------------------------
    def stop_scan(self):
        """Ask the active Nmap process to stop and return the controls to an idle state."""
        self.is_scanning = False  # Signal the run_scan thread to stop forwarding output.
        if self.scan_process is not None and self.scan_process.poll() is None:
            self.scan_process.terminate()  # Kill Nmap.
        self.log("[!] ASSESSMENT ABORTED")
        self.finish_scan("ABORTED")

    # -----------------------------------------------------------------------
    # finish_scan — Reset buttons, progress bar, and status text after any
    # scan ends (complete, aborted, or error).
    # -----------------------------------------------------------------------
    def finish_scan(self, status):
        """Restore buttons and progress indicators after any scan completion state."""
        self.is_scanning = False
        self.progress.stop()
        self.progress["value"] = 0
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.open_report_btn.config(state=tk.NORMAL if self.last_report else tk.DISABLED)
        self.status_label.config(text=status, fg=self.ACCENT if status == "COMPLETE" else self.MUTED)

    # -----------------------------------------------------------------------
    # open_report — Open the latest HTML report in the default browser.
    # -----------------------------------------------------------------------
    def open_report(self):
        """Open the latest HTML report with the operating system's default browser."""
        if self.last_report:
            webbrowser.open(self.last_report.as_uri())

    # -----------------------------------------------------------------------
    # export_report — Open the JSON/CSV/TXT version of the latest report.
    # -----------------------------------------------------------------------
    def export_report(self, extension):
        """Open a matching JSON, CSV, or TXT file for the latest report."""
        if self.last_report:
            path = self.last_report.with_suffix("." + extension)
            if path.exists():
                webbrowser.open(path.as_uri())

    # =======================================================================
    # VERSION 2 DASHBOARD
    # The methods below intentionally redefine build_ui() and show_history()
    # so the Version 2 dashboard replaces the legacy Version 1 look. The
    # underlying scan / report pipeline is untouched.
    # =======================================================================
    def build_ui(self):
        """
        Build the active Version 2 dashboard UI.

        Layout (from top to bottom, left to right):
        - Header bar with logo, nav buttons, and "NMAP GUI" label.
        - Left sidebar (322px) with all scan-configuration fields + Start/Stop.
        - Right content area with:
            * Title & target subtitle
            * Four summary cards (Hosts up / Open ports / Findings / Duration)
            * A tabbed area: Overview, Ports & Services, Script output,
              Live output, Export.
        """
        self.root.title("NIGHTHAWK 2.0.0 — Advanced Network Scanner")
        self.root.geometry("1530x960")
        self.root.minsize(1180, 760)
        self.root.configure(bg="#020b16")
        self.root.grid_rowconfigure(1, weight=1)   # Row 1 (main shell) grows.
        self.root.grid_columnconfigure(0, weight=1)

        # --- ttk Style definitions: Notebook, Treeview, ProgressBar -----
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Nighthawk.Horizontal.TProgressbar", troughcolor=self.PANEL,
                        background=self.ACCENT, bordercolor=self.PANEL,
                        lightcolor=self.ACCENT, darkcolor=self.ACCENT)
        style.configure("Nighthawk.TNotebook", background=self.BG, borderwidth=0)
        style.configure("Nighthawk.TNotebook.Tab", background=self.PANEL, foreground=self.MUTED,
                        padding=(22, 10), font=("Segoe UI", 10, "bold"))
        style.map("Nighthawk.TNotebook.Tab", background=[("selected", self.ACCENT)],
                  foreground=[("selected", "white")])
        style.configure("Nighthawk.Treeview", background=self.PANEL, fieldbackground=self.PANEL,
                        foreground=self.FG, rowheight=28, borderwidth=0,
                        font=("Segoe UI", 10))
        style.configure("Nighthawk.Treeview.Heading", background="#202020", foreground=self.FG,
                        font=("Segoe UI", 9, "bold"), relief=tk.FLAT)
        style.map("Nighthawk.Treeview", background=[("selected", "#263B54")])

        # --- HEADER -------------------------------------------------------
        header = tk.Frame(self.root, bg="#020b16", height=74)
        header.grid(row=0, column=0, sticky="ew")
        header.grid_columnconfigure(8, weight=1)  # Push "NMAP GUI" to the right.

        # Logo image (logo.png next to this file). Fallback to a letter "N".
        logo_path = Path(__file__).with_name("logo.png")
        try:
            self.logo_image = tk.PhotoImage(file=logo_path).subsample(8, 8)  # Shrink 8x.
            tk.Label(header, image=self.logo_image, bg="#020b16").grid(row=0, column=0, padx=(18, 8), pady=6)
        except tk.TclError:
            tk.Label(header, text="N", bg="#020b16", fg=self.ACCENT, font=("Segoe UI", 26, "bold")).grid(row=0, column=0, padx=(18, 8), pady=8)

        # Brand text.
        brand = tk.Frame(header, bg="#020b16")
        brand.grid(row=0, column=1, sticky="w")
        tk.Label(brand, text="NIGHTHAWK", bg="#020b16", fg="#47caff", font=("Segoe UI", 23, "bold")).pack(anchor="w")
        tk.Label(brand, text="ADVANCED NETWORK SCANNER  •  VERSION 2", bg="#020b16", fg="#5e94c8", font=("Segoe UI", 8, "bold")).pack(anchor="w")

        # Navigation buttons: Scan / Reports / Settings / About.
        self._v2_nav_button(header, "◉\nScan", lambda: self.dashboard_tabs.select(self.overview_tab), True).grid(row=0, column=2, padx=(48, 0), sticky="ns")
        self._v2_nav_button(header, "▤\nReports", self.show_history).grid(row=0, column=3, sticky="ns")
        self._v2_nav_button(header, "⚙\nSettings", self.show_settings_hint).grid(row=0, column=4, sticky="ns")
        self._v2_nav_button(header, "ⓘ\nAbout", self.show_about).grid(row=0, column=5, sticky="ns")
        tk.Label(header, text="NMAP GUI", bg="#020b16", fg="#5f82a6", font=("Segoe UI", 9, "bold")).grid(row=0, column=8, sticky="e", padx=22)

        # --- MAIN SHELL: Sidebar (left) + Content (right) ----------------
        shell = tk.Frame(self.root, bg="#020b16")
        shell.grid(row=1, column=0, sticky="nsew", padx=10, pady=(0, 10))
        shell.grid_rowconfigure(0, weight=1)
        shell.grid_columnconfigure(1, weight=1)  # Right column is stretchy.

        # Left sidebar (fixed width 322px).
        sidebar = tk.Frame(shell, bg="#05111f", width=322, highlightbackground="#1260a8", highlightthickness=1)
        sidebar.grid(row=0, column=0, sticky="nsw", padx=(0, 10))
        sidebar.grid_propagate(False)  # Force the width to stay fixed.
        self._build_v2_sidebar(sidebar)

        # Right content area (stretchy).
        content = tk.Frame(shell, bg="#020b16")
        content.grid(row=0, column=1, sticky="nsew")
        content.grid_rowconfigure(4, weight=1)   # The tab area expands.
        content.grid_columnconfigure(0, weight=1)
        self._build_v2_content(content)

        # Apply the black/gray SOC palette to the whole window (this rewrites
        # a bunch of hard-coded blue colors left over from the layout code).
        self._apply_v2_palette()
        self.scan_type_changed(self.scan_type.get())

    # -----------------------------------------------------------------------
    # _apply_v2_palette — Walk the whole widget tree and remap old blue-ish
    # colors to the new black/gray SOC palette. This keeps the code readable
    # while enforcing the color theme in one place.
    # -----------------------------------------------------------------------
    def _apply_v2_palette(self):
        """Apply a restrained SOC-dashboard palette to the Version 2 layout."""
        # Map: old color → new color.
        colors = {
            "#020b16": self.BG, "#030d18": "#101010", "#05111f": self.PANEL,
            "#061321": self.PANEL, "#06192c": self.PANEL, "#071524": self.PANEL,
            "#081a2b": "#1f1f1f", "#091d31": "#101010", "#0a2037": "#202020",
            "#0b2948": "#202020", "#0b3d70": "#202020", "#123653": "#333333",
            "#124f9a": "#202020", "#1260a8": "#333333", "#1265df": self.ACCENT,
            "#153b70": "#202020", "#162b40": "#202020", "#164f96": "#333333",
            "#1686ff": self.ACCENT, "#1b4d78": "#333333", "#1c4b74": "#333333",
            "#27669c": "#333333", "#25b9ff": self.ACCENT, "#42e692": self.HEALTHY,
            "#47caff": self.ACCENT, "#4ca7ff": self.ACCENT, "#4fd7ff": self.ACCENT,
            "#4fe2e0": self.ACCENT, "#52e99a": self.ACCENT, "#57ed9f": self.ACCENT,
            "#5e94c8": self.MUTED, "#5f82a6": self.MUTED, "#75c6ff": self.ACCENT,
            "#78a5d2": self.MUTED, "#82a9d7": self.MUTED, "#88aaca": self.MUTED,
            "#8fb4d8": self.MUTED, "#91b2d3": self.MUTED, "#9bbad8": self.MUTED,
            "#9eb9d8": self.MUTED, "#9fc2e5": self.MUTED, "#9fc9f4": self.MUTED,
            "#b7d4ef": self.FG, "#b9d8ff": self.FG, "#b9ddff": self.FG,
            "#bcd7ff": self.FG, "#bfd8f3": self.FG, "#c8ddf4": self.FG,
            "#c8e0ff": self.FG, "#c8e2ff": self.FG, "#d7e9ff": self.FG,
            "#d9eaff": self.FG, "#e1efff": self.FG, "#e3f2ff": self.FG,
            "#e6f2ff": self.FG, "#ec3545": self.ACCENT, "#ff5c65": "#5A89C9", "#240018": "#101010",
        }

        def recolor(widget):
            """Recursively recolor this widget and all its descendants."""
            for option in ("background", "foreground", "activebackground", "activeforeground",
                           "insertbackground", "highlightbackground", "highlightcolor", "selectcolor"):
                try:
                    current = str(widget.cget(option)).lower()
                    if current in colors:
                        widget.configure(**{option: colors[current]})
                except tk.TclError:
                    pass  # Some widgets don't support this option; ignore.
            for child in widget.winfo_children():
                recolor(child)

        recolor(self.root)
        self._draw_risk(self.ACCENT)  # Repaint the risk ring with the new palette.

    # -----------------------------------------------------------------------
    # _v2_nav_button — Small helper to make a top-nav button.
    # -----------------------------------------------------------------------
    def _v2_nav_button(self, parent, text, command, active=False):
        """Create one small top-navigation button for the Version 2 header."""
        return tk.Button(parent, text=text, command=command,
                         bg="#153b70" if active else "#020b16",
                         fg="#e3f2ff" if active else "#9fc9f4",
                         activebackground="#164f96", activeforeground="white",
                         relief=tk.FLAT, bd=0, padx=22, pady=12,
                         font=("Segoe UI", 10, "bold"), justify=tk.CENTER, cursor="hand2")

    # -----------------------------------------------------------------------
    # _v2_title — Section heading inside a panel.
    # -----------------------------------------------------------------------
    def _v2_title(self, parent, text):
        """Add a readable section heading inside a Version 2 panel."""
        tk.Label(parent, text=text, bg=parent.cget("bg"), fg="#d7e9ff",
                 font=("Segoe UI", 11, "bold")).pack(anchor="w", padx=14, pady=(13, 6))

    # -----------------------------------------------------------------------
    # _v2_field — Place a label above a form widget and pack the widget.
    # -----------------------------------------------------------------------
    def _v2_field(self, parent, label, widget):
        """Place a plain-language field label directly above a form widget."""
        tk.Label(parent, text=label, bg="#05111f", fg="#d7e9ff", font=("Segoe UI", 10, "bold")).pack(anchor="w", padx=14, pady=(10, 4))
        widget.pack(fill=tk.X, padx=14)

    # -----------------------------------------------------------------------
    # _v2_entry — Single-line text field with a starting value.
    # -----------------------------------------------------------------------
    def _v2_entry(self, parent, value=""):
        """Create a Version 2 text-entry control with a starting value."""
        entry = tk.Entry(parent, bg="#091d31", fg="#e6f2ff", insertbackground="#25b9ff",
                         relief=tk.FLAT, highlightthickness=1, highlightbackground="#27669c",
                         highlightcolor="#25b9ff", font=("Segoe UI", 11))
        entry.insert(0, value)
        return entry

    # -----------------------------------------------------------------------
    # _v2_menu — Styled drop-down menu.
    # -----------------------------------------------------------------------
    def _v2_menu(self, parent, variable, values, command=None):
        """Create a styled drop-down menu connected to a Tkinter variable."""
        menu = tk.OptionMenu(parent, variable, *values, command=command)
        menu.config(bg="#091d31", fg="#e6f2ff", activebackground="#164f96", activeforeground="white",
                    relief=tk.FLAT, highlightthickness=1, highlightbackground="#27669c", anchor="w",
                    font=("Segoe UI", 10), padx=9)
        menu["menu"].config(bg="#091d31", fg="#e6f2ff", activebackground="#164f96")
        return menu

    # -----------------------------------------------------------------------
    # _build_v2_sidebar — Left panel: profile, target, ports, scan type,
    # timing, scan options, extra flags, and Start/Stop buttons.
    # -----------------------------------------------------------------------
    def _build_v2_sidebar(self, sidebar):
        """Build the left-side scan form while reusing all original scanner variables."""
        self._v2_title(sidebar, "Scan configuration")

        # Profile selection.
        self.profile_var = tk.StringVar(value=self.config.get("profile", "Custom / Manual"))
        self.profile_menu = self._v2_menu(sidebar, self.profile_var, list(self.PROFILES), self.apply_profile)
        self._v2_field(sidebar, "Profile", self.profile_menu)

        # Target entry.
        self.target_entry = self._v2_entry(sidebar, self.config.get("target", "127.0.0.1"))
        self._v2_field(sidebar, "Target", self.target_entry)

        # Port range entry + preset dropdown.
        self.port_entry = self._v2_entry(sidebar, self.config.get("ports", "1-1024"))
        self._v2_field(sidebar, "Port range", self.port_entry)
        self.port_dropdown = tk.StringVar(value="Custom")
        ports_menu = self._v2_menu(sidebar, self.port_dropdown, ["Custom", "Top 100", "Top 1000", "All"], self.apply_port_preset)
        ports_menu.pack(fill=tk.X, padx=14, pady=(5, 0))

        # Scan type dropdown (skip the "---" separator entries).
        self.scan_type = tk.StringVar(value=self.config.get("scan_type", "TCP Connect (-sT)"))
        scan_choices = [name for name in self.SCAN_TYPES if not name.startswith("---")]
        self.scan_menu = self._v2_menu(sidebar, self.scan_type, scan_choices, self.scan_type_changed)
        self._v2_field(sidebar, "Scan type", self.scan_menu)

        # Timing dropdown.
        self.timing_var = tk.StringVar(value=self.config.get("timing", "Insane (T5)"))
        timing_menu = self._v2_menu(sidebar, self.timing_var, list(self.TIMING_TEMPLATES))
        self._v2_field(sidebar, "Timing", timing_menu)

        # Scan options (checkboxes).
        self.options_frame = tk.Frame(sidebar, bg="#05111f")
        self.options_frame.pack(fill=tk.X, padx=10, pady=(12, 0))
        tk.Label(self.options_frame, text="Scan options", bg="#05111f", fg="#d7e9ff", font=("Segoe UI", 10, "bold")).pack(anchor="w", padx=4, pady=(0, 4))
        self.service_var = tk.BooleanVar(value=self.config.get("service", True))
        self.os_var = tk.BooleanVar(value=self.config.get("os", False))
        self.nse_default = tk.BooleanVar(value=False)
        self.nse_vuln = tk.BooleanVar(value=False)
        self.nse_http = tk.BooleanVar(value=False)
        self.nse_ssl = tk.BooleanVar(value=False)
        for text, variable in (("Service detection (-sV)", self.service_var), ("OS detection (-O)", self.os_var),
                               ("Default scripts (-sC)", self.nse_default), ("Vulnerability scripts", self.nse_vuln),
                               ("HTTP enumeration", self.nse_http), ("SSL cipher audit", self.nse_ssl)):
            tk.Checkbutton(self.options_frame, text=text, variable=variable, bg="#05111f", fg="#c8ddf4",
                           selectcolor="#0b3d70", activebackground="#05111f", activeforeground="white",
                           font=("Segoe UI", 9), anchor="w", relief=tk.FLAT).pack(fill=tk.X, padx=2, pady=1)

        # Custom-flags entry (hidden until "Custom Flags" scan type is chosen).
        self.custom_frame = tk.Frame(sidebar, bg="#05111f")
        self.custom_entry = self._v2_entry(self.custom_frame, "-sT -sV --reason")
        self._v2_field(self.custom_frame, "Custom Nmap flags", self.custom_entry)
        self.custom_frame.pack_forget()

        # Extra flags entry (always visible).
        self.extra_entry = self._v2_entry(sidebar, self.config.get("extra_flags", "--reason"))
        self._v2_field(sidebar, "Extra flags", self.extra_entry)
        self.entries = {"TARGET": self.target_entry}

        # Auto-open HTML toggle.
        self.auto_open_var = tk.BooleanVar(value=self.config.get("auto_open", True))
        tk.Checkbutton(sidebar, text="Open HTML report when complete", variable=self.auto_open_var, bg="#05111f", fg="#8fb4d8",
                       selectcolor="#0b3d70", activebackground="#05111f", activeforeground="white",
                       font=("Segoe UI", 9), anchor="w", relief=tk.FLAT).pack(fill=tk.X, padx=14, pady=(10, 6))

        # Quick tools: Save preset + Cheatsheet.
        quick_tools = tk.Frame(sidebar, bg="#05111f")
        quick_tools.pack(fill=tk.X, padx=14, pady=(0, 8))
        self.save_fav_btn = tk.Button(quick_tools, text="SAVE PRESET", command=self.save_favorite, bg="#0b2948", fg="#b9ddff",
                                      activebackground="#164f96", activeforeground="white", relief=tk.FLAT,
                                      font=("Segoe UI", 8, "bold"), padx=8, pady=6)
        self.save_fav_btn.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 3))
        tk.Button(quick_tools, text="? CHEATSHEET", command=self.show_cheatsheet, bg="#0b2948", fg="#b9ddff",
                  activebackground="#164f96", activeforeground="white", relief=tk.FLAT,
                  font=("Segoe UI", 8, "bold"), padx=8, pady=6).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(3, 0))

        # Start / Stop buttons (pinned to bottom of sidebar).
        actions = tk.Frame(sidebar, bg="#05111f")
        actions.pack(fill=tk.X, side=tk.BOTTOM, padx=14, pady=14)
        self.start_btn = tk.Button(actions, text="▶  START SCAN", command=self.start_scan, bg=self.ACCENT, fg="#ffffff",
                                   activebackground="#5A89C9", activeforeground="#ffffff", relief=tk.FLAT,
                                   font=("Segoe UI", 12, "bold"), pady=11, cursor="hand2")
        self.start_btn.pack(fill=tk.X)
        self.stop_btn = tk.Button(actions, text="■  STOP", command=self.stop_scan, bg="#162b40", fg="#b7d4ef",
                                  activebackground="#294b6c", activeforeground="white", relief=tk.FLAT,
                                  font=("Segoe UI", 9, "bold"), pady=6, state=tk.DISABLED)
        self.stop_btn.pack(fill=tk.X, pady=(6, 0))

    # -----------------------------------------------------------------------
    # _summary_card — One "KPI" card (Hosts up, Open ports, etc.).
    # -----------------------------------------------------------------------
    def _summary_card(self, parent, title, variable, color):
        """Create one compact scan total card, such as open ports or scan duration."""
        card = tk.Frame(parent, bg="#071524", highlightbackground="#1b4d78", highlightthickness=1)
        tk.Label(card, text=title.upper(), bg="#071524", fg="#88aaca", font=("Segoe UI", 8, "bold")).pack(anchor="w", padx=14, pady=(10, 2))
        tk.Label(card, textvariable=variable, bg="#071524", fg=color, font=("Segoe UI", 18, "bold")).pack(anchor="w", padx=14, pady=(0, 10))
        return card

    # -----------------------------------------------------------------------
    # _build_v2_content — Right-hand panel: heading, summary cards, and tabs.
    # -----------------------------------------------------------------------
    def _build_v2_content(self, content):
        """Build the main dashboard area and its Overview, Ports, Scripts, and Export tabs."""
        # --- Heading (title + subtitle + status pill) --------------------
        heading = tk.Frame(content, bg="#020b16")
        heading.grid(row=0, column=0, sticky="ew", pady=(0, 8))
        heading.grid_columnconfigure(0, weight=1)
        self.report_title_var = tk.StringVar(value="Ready to scan")
        self.report_target_var = tk.StringVar(value="Target: choose a host in the scan panel")
        tk.Label(heading, textvariable=self.report_title_var, bg="#020b16", fg="#bcd7ff", font=("Segoe UI", 22, "bold")).grid(row=0, column=0, sticky="w")
        tk.Label(heading, textvariable=self.report_target_var, bg="#020b16", fg="#82a9d7", font=("Segoe UI", 12)).grid(row=1, column=0, sticky="w")
        self.status_label = tk.Label(heading, text="READY", bg="#06192c", fg="#4fd7ff", font=("Segoe UI", 9, "bold"), padx=14, pady=8)
        self.status_label.grid(row=0, column=1, rowspan=2, sticky="e")

        # --- Summary cards ----------------------------------------------
        cards = tk.Frame(content, bg="#020b16")
        cards.grid(row=1, column=0, sticky="ew", pady=(0, 10))
        for col in range(4):
            cards.grid_columnconfigure(col, weight=1)
        self.host_count_var = tk.StringVar(value="—")
        self.open_ports_var = tk.StringVar(value="—")
        self.findings_var = tk.StringVar(value="—")
        self.duration_var = tk.StringVar(value="—")
        for col, (title, var, color) in enumerate((
            ("Hosts up", self.host_count_var, "#3ddc97"),
            ("Open ports", self.open_ports_var, self.ACCENT),
            ("Script findings", self.findings_var, self.ERROR),
            ("Scan duration", self.duration_var, self.WARN),
        )):
            self._summary_card(cards, title, var, color).grid(
                row=0, column=col, sticky="ew", padx=(0 if col == 0 else 7, 0))

        # --- Tabbed area -------------------------------------------------
        self.dashboard_tabs = ttk.Notebook(content, style="Nighthawk.TNotebook")
        self.dashboard_tabs.grid(row=4, column=0, sticky="nsew")
        self.overview_tab = tk.Frame(self.dashboard_tabs, bg="#020b16")
        ports_tab = tk.Frame(self.dashboard_tabs, bg="#020b16")
        scripts_tab = tk.Frame(self.dashboard_tabs, bg="#020b16")
        live_tab = tk.Frame(self.dashboard_tabs, bg="#020b16")
        export_tab = tk.Frame(self.dashboard_tabs, bg="#020b16")
        self.dashboard_tabs.add(self.overview_tab, text="Overview")
        self.dashboard_tabs.add(ports_tab, text="Ports & Services")
        self.dashboard_tabs.add(scripts_tab, text="Script output")
        self.dashboard_tabs.add(live_tab, text="Live output")
        self.dashboard_tabs.add(export_tab, text="Export")

        # Build the content of each tab.
        self._build_v2_overview(self.overview_tab)
        self._build_v2_ports(ports_tab)
        self._build_v2_scripts(scripts_tab)
        self._build_v2_live(live_tab)
        self._build_v2_export(export_tab)

    # -----------------------------------------------------------------------
    # _build_v2_overview — The Overview tab: target metadata + risk gauge.
    # -----------------------------------------------------------------------
    def _build_v2_overview(self, tab):
        """Build target metadata and the risk-assessment panel for the Overview tab."""
        tab.grid_columnconfigure(0, weight=3)
        tab.grid_columnconfigure(1, weight=2)

        # Left: "Target information" table with key/value rows.
        info = tk.Frame(tab, bg="#061321", highlightbackground="#1c4b74", highlightthickness=1)
        info.grid(row=0, column=0, sticky="nsew", padx=(0, 8), pady=8)
        tk.Label(info, text="◉  Target information", bg="#061321", fg="#4fe2e0", font=("Segoe UI", 12, "bold")).pack(anchor="w", padx=15, pady=12)
        # Dict of StringVars so refresh_dashboard() can update them later.
        self.info_vars = {key: tk.StringVar(value="—") for key in ("IP address", "MAC address", "Operating system", "Network distance", "Service info")}
        for key, variable in self.info_vars.items():
            row = tk.Frame(info, bg="#081a2b")
            row.pack(fill=tk.X, padx=15, pady=1)
            tk.Label(row, text=key, width=18, anchor="w", bg="#081a2b", fg="#9fc2e5", font=("Segoe UI", 9)).pack(side=tk.LEFT, padx=8, pady=6)
            tk.Label(row, textvariable=variable, anchor="w", bg="#081a2b", fg="#e1efff", font=("Segoe UI", 9)).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=8)

        # Right: risk-assessment gauge.
        risk = tk.Frame(tab, bg="#061321", highlightbackground="#1c4b74", highlightthickness=1)
        risk.grid(row=0, column=1, sticky="nsew", pady=8)
        tk.Label(risk, text="◉  Risk assessment", bg="#061321", fg="#4fe2e0", font=("Segoe UI", 12, "bold")).pack(anchor="w", padx=15, pady=12)
        self.risk_canvas = tk.Canvas(risk, width=210, height=190, bg="#061321", highlightthickness=0)
        self.risk_canvas.pack(side=tk.LEFT, padx=12, pady=2)
        self.risk_label = tk.StringVar(value="AWAITING\nSCAN")
        self._draw_risk("#1686ff")
        legend = tk.Frame(risk, bg="#061321")
        legend.pack(side=tk.LEFT, fill=tk.Y, padx=4)
        self.risk_detail_var = tk.StringVar(value="Run a scan to assess\nopen services and scripts.")
        tk.Label(legend, textvariable=self.risk_detail_var, justify=tk.LEFT, bg="#061321", fg="#bfd8f3", font=("Segoe UI", 10)).pack(anchor="w", pady=(53, 0))

    # -----------------------------------------------------------------------
    # _draw_risk — Draw the risk ring (two circles + two text labels).
    # -----------------------------------------------------------------------
    def _draw_risk(self, color):
        """Redraw the simple risk ring using the severity color selected for this scan."""
        self.risk_canvas.delete("all")
        # Outer dim ring (background).
        self.risk_canvas.create_oval(37, 25, 173, 161, outline="#2b3540", width=9)
        # Colored arc on top of it (270 degrees).
        self.risk_canvas.create_arc(37, 25, 173, 161, start=90, extent=270, style=tk.ARC, outline=color, width=9)
        # Center label text (e.g., "HIGH RISK").
        self.risk_canvas.create_text(105, 84, text=self.risk_label.get(), fill=color, font=("Segoe UI", 13, "bold"), justify=tk.CENTER)
        # Small caption under the label.
        self.risk_canvas.create_text(105, 125, text="assessment", fill="#8e9baa", font=("Segoe UI", 8), justify=tk.CENTER)

    # -----------------------------------------------------------------------
    # _risk_assessment — Decide one severity label from scan results.
    # Rules (checked in order):
    #   1. Critical script evidence (exploit / RCE) → CRITICAL
    #   2. High-risk script evidence (vulnerable / CVE) → HIGH RISK
    #   3. Any script findings at all → REVIEW
    #   4. Any open ports → EXPOSED
    #   5. Nothing at all → CLEAR
    # -----------------------------------------------------------------------
    def _risk_assessment(self, records):
        """Return one severity decision for both the desktop and HTML reports."""
        open_ports = [record for record in records if record.get("state") == "open"]
        scripts = [script for record in records for script in record.get("scripts", [])]
        script_text = " ".join(str(script.get("output", "")) for script in scripts).casefold()
        if any(term in script_text for term in ("critical", "exploit", "remote code execution")):
            return {"label": "CRITICAL", "color": self.CRITICAL, "css": "risk-critical", "detail": "Critical exploit evidence detected."}
        if any(term in script_text for term in ("vulnerable", "cve-", "high severity")):
            return {"label": "HIGH RISK", "color": self.ERROR, "css": "risk-high", "detail": "High-risk vulnerability evidence detected."}
        if scripts:
            return {"label": "REVIEW", "color": self.ORANGE, "css": "risk-review", "detail": "Script findings require review."}
        if open_ports:
            return {"label": "EXPOSED", "color": self.WARN, "css": "risk-exposed", "detail": "Open services were detected."}
        return {"label": "CLEAR", "color": self.HEALTHY, "css": "risk-clear", "detail": "No open services or script findings."}

    # -----------------------------------------------------------------------
    # _build_v2_ports — Sortable-looking table of port results.
    # -----------------------------------------------------------------------
    def _build_v2_ports(self, tab):
        """Create the sortable-looking table that lists parsed Nmap port results."""
        columns = ("port", "state", "service", "version", "reason")
        self.port_table = ttk.Treeview(tab, columns=columns, show="headings", style="Nighthawk.Treeview")
        for name, width in (("port", 110), ("state", 110), ("service", 160), ("version", 340), ("reason", 170)):
            self.port_table.heading(name, text=name.upper())
            self.port_table.column(name, width=width, anchor="w")
        self.port_table.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)
        # Row tags let us color open rows green and closed rows red.
        self.port_table.tag_configure("open", foreground="#3ddc97")
        self.port_table.tag_configure("closed", foreground=self.ERROR)

    # -----------------------------------------------------------------------
    # _build_v2_scripts — Read-only text area for NSE script output.
    # -----------------------------------------------------------------------
    def _build_v2_scripts(self, tab):
        """Create the read-only area used to display Nmap NSE script output."""
        self.scripts_view = scrolledtext.ScrolledText(tab, state=tk.DISABLED, bg="#061321", fg="#d9eaff", insertbackground="#25b9ff",
                                                       relief=tk.FLAT, font=("Cascadia Mono", 10), padx=14, pady=14)
        self.scripts_view.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)

    # -----------------------------------------------------------------------
    # _build_v2_live — Live-output tab: command preview, progress bar,
    # MAC/OS info line, and the scrolling Nmap log.
    # -----------------------------------------------------------------------
    def _build_v2_live(self, tab):
        """Create the command preview, progress bar, host info, and live output tab."""
        top = tk.Frame(tab, bg="#020b16")
        top.pack(fill=tk.X, padx=8, pady=(8, 0))
        self.command_var = tk.StringVar(value="Waiting for scan configuration…")
        tk.Label(top, text="COMMAND", bg="#020b16", fg="#78a5d2", font=("Segoe UI", 9, "bold")).pack(side=tk.LEFT, padx=(0, 8))
        tk.Label(top, textvariable=self.command_var, bg="#061321", fg="#75c6ff", anchor="w", font=("Cascadia Mono", 9), padx=10, pady=8).pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.progress = ttk.Progressbar(top, mode="indeterminate", length=160, style="Nighthawk.Horizontal.TProgressbar")
        self.progress.pack(side=tk.RIGHT, padx=(10, 0))

        self.live_info_label = tk.Label(tab, text="MAC: ---  |  OS: ---", bg="#020b16", fg="#9bbad8", font=("Segoe UI", 9, "bold"), anchor="w")
        self.live_info_label.pack(fill=tk.X, padx=8, pady=8)

        self.output = scrolledtext.ScrolledText(tab, state=tk.DISABLED, bg="#030d18", fg="#c8e0ff", insertbackground="#25b9ff",
                                                relief=tk.FLAT, font=("Cascadia Mono", 10), padx=14, pady=14)
        self.output.pack(fill=tk.BOTH, expand=True, padx=8, pady=(0, 8))
        self.output.tag_config("open", foreground="#3ddc97")
        self.output.tag_config("closed", foreground=self.WARN)
        self.output.tag_config("error", foreground=self.ERROR)

    # -----------------------------------------------------------------------
    # _build_v2_export — Export tab: buttons to open reports/history.
    # -----------------------------------------------------------------------
    def _build_v2_export(self, tab):
        """Create buttons for opening the latest report and its export formats."""
        tk.Label(tab, text="Export completed scan reports", bg="#020b16", fg="#d7e9ff", font=("Segoe UI", 16, "bold")).pack(anchor="w", padx=22, pady=(24, 5))
        tk.Label(tab, text="NIGHTHAWK saves HTML, JSON, CSV, and TXT reports in the reports folder.", bg="#020b16", fg="#91b2d3", font=("Segoe UI", 10)).pack(anchor="w", padx=22, pady=(0, 20))

        buttons = tk.Frame(tab, bg="#020b16")
        buttons.pack(anchor="w", padx=22)

        self.open_report_btn = tk.Button(buttons, text="OPEN HTML REPORT", command=self.open_report,
                                          bg="#1265df", fg="white", relief=tk.FLAT,
                                          font=("Segoe UI", 10, "bold"), padx=14, pady=10, state=tk.DISABLED)
        self.open_report_btn.pack(side=tk.LEFT, padx=(0, 8))

        for label, ext in (("JSON", "json"), ("CSV", "csv"), ("TXT", "txt")):
            tk.Button(buttons, text=label, command=lambda e=ext: self.export_report(e),
                      bg="#0b2948", fg="#c8e2ff", relief=tk.FLAT,
                      font=("Segoe UI", 10, "bold"), padx=14, pady=10).pack(side=tk.LEFT, padx=4)

        tk.Button(tab, text="SCAN HISTORY & DIFF", command=self.show_history,
                  bg="#0b2948", fg="#c8e2ff", relief=tk.FLAT,
                  font=("Segoe UI", 10, "bold"), padx=14, pady=10).pack(anchor="w", padx=22, pady=16)

    # -----------------------------------------------------------------------
    # scan_type_changed (Version 2 override)
    # Shows "Custom Nmap flags" only when the scan type is "Custom Flags".
    # Also disables the standard options for evasion-only scan types.
    # -----------------------------------------------------------------------
    def scan_type_changed(self, selected):
        """Show custom flags only when needed; normal scan choices keep the standard form."""
        custom_types = {"Custom Flags", "Fragment Packets (-f)", "Custom MTU (--mtu 24)",
                        "Decoy Scan (-D RND:10)", "Spoof MAC (--spoof-mac 0)",
                        "Bad Checksum (--badsum)", "Idle Scan (-sI)", "Source Port Spoof (-g 53)"}
        if selected == "Custom Flags":
            self.custom_frame.pack(fill=tk.X, before=self.extra_entry, padx=0, pady=0)
        else:
            self.custom_frame.pack_forget()
        if selected in custom_types:
            self.options_frame.configure(bg="#05111f")

    # -----------------------------------------------------------------------
    # refresh_dashboard — Called after a successful scan to update every
    # dashboard widget with the new data (cards, info rows, tables, gauge).
    # -----------------------------------------------------------------------
    def refresh_dashboard(self, data):
        """Copy newly parsed scan data into every Version 2 dashboard widget."""
        results = data.get("results", [])
        open_ports = [item for item in results if item.get("state") == "open"]
        scripts = [script for item in results for script in item.get("scripts", [])]
        target = data.get("target", "Unknown")
        info = data.get("info", {})

        # Title & subtitle.
        self.report_title_var.set("Scan report")
        self.report_target_var.set(f"Target: {target}")

        # Summary cards.
        self.host_count_var.set("1")
        self.open_ports_var.set(str(len(open_ports)))
        self.findings_var.set(str(len(scripts)))
        if hasattr(self, "scan_started_at"):
            self.duration_var.set(str(datetime.datetime.now() - self.scan_started_at).split(".")[0])

        # Target info rows.
        self.info_vars["IP address"].set(target)
        self.info_vars["MAC address"].set(info.get("mac", "Unknown"))
        self.info_vars["Operating system"].set(info.get("os", "Unknown"))
        self.info_vars["Network distance"].set(info.get("distance", "Unknown"))
        self.info_vars["Service info"].set(info.get("service_info", "Unknown"))

        # Ports table — clear then re-populate.
        for item in self.port_table.get_children():
            self.port_table.delete(item)
        for item in results:
            version = " ".join(part for part in (item.get("product", ""), item.get("version", ""), item.get("extrainfo", "")) if part).strip()
            self.port_table.insert(
                "", tk.END,
                values=(f"{item.get('port')}/{item.get('protocol')}", item.get("state", ""), item.get("service", ""),
                        version or "—", item.get("reason", "")),
                tags=("open" if item.get("state") == "open" else "closed",)
            )

        # Script output area.
        self.scripts_view.config(state=tk.NORMAL)
        self.scripts_view.delete("1.0", tk.END)
        if scripts:
            for item in results:
                for script in item.get("scripts", []):
                    self.scripts_view.insert(tk.END, f"[{item.get('port')}/{item.get('protocol')}] {script.get('id')}\n{script.get('output')}\n\n")
        else:
            self.scripts_view.insert(tk.END, "No Nmap script output was returned for this scan.")
        self.scripts_view.config(state=tk.DISABLED)

        # Risk gauge.
        assessment = self._risk_assessment(results)
        self.risk_label.set(assessment["label"].replace(" ", "\n"))
        self._draw_risk(assessment["color"])
        self.risk_detail_var.set(f"{assessment['detail']}\n{len(scripts)} script finding(s) · {len(open_ports)} open port(s)")

        # Switch back to the Overview tab so the user sees the summary.
        self.dashboard_tabs.select(self.overview_tab)

    # -----------------------------------------------------------------------
    # show_settings_hint — Tiny info dialog explaining where settings live.
    # -----------------------------------------------------------------------
    def show_settings_hint(self):
        """Explain where scan settings are located without opening a separate settings system."""
        messagebox.showinfo("Settings", "Scan settings are available in the left configuration panel.")

    # -----------------------------------------------------------------------
    # show_about — Tiny About dialog with a safety reminder.
    # -----------------------------------------------------------------------
    def show_about(self):
        """Show a short, safe about message for the application."""
        messagebox.showinfo("About NIGHTHAWK", "NIGHTHAWK 2.0.0\nAdvanced Network Scanner\n\nOnly scan hosts you own or have permission to test.")

    # -----------------------------------------------------------------------
    # _dashboard_report_page — Generate the HTML report shown in the browser.
    # This is a big f-string that:
    #   1. Reads the parsed scan data (records, info, scripts).
    #   2. Computes risk assessment.
    #   3. Builds HTML for tables, script blocks, and metadata.
    #   4. Embeds a small JS block that handles filter + download buttons.
    # -----------------------------------------------------------------------
    def _dashboard_report_page(self, data, base):
        """Create a standalone browser report using the same dashboard language as the app."""
        records = data.get("results", [])
        info = data.get("info", {})
        open_ports = [record for record in records if record.get("state") == "open"]
        scripts = [script for record in records for script in record.get("scripts", [])]
        assessment = self._risk_assessment(records)
        risk = assessment["label"]
        risk_class = assessment["css"]

        # Build one <tr> per port.
        rows = []
        for record in records:
            version = " ".join(part for part in (record.get("product", ""), record.get("version", ""), record.get("extrainfo", "")) if part).strip() or "—"
            state = html.escape(str(record.get("state", "")))
            state_class = "state-open" if state == "open" else "state-other"
            rows.append(
                "<tr><td>{}</td><td class='{}'>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>".format(
                    html.escape(f"{record.get('port', '')}/{record.get('protocol', '')}"),
                    state_class, state,
                    html.escape(str(record.get("service", "") or "—")),
                    html.escape(version),
                    html.escape(str(record.get("reason", "") or "—"))
                )
            )
        if not rows:
            rows.append("<tr><td colspan='5' class='empty'>No port results were returned.</td></tr>")

        # Build one <article> per script finding.
        script_blocks = []
        for record in records:
            for script in record.get("scripts", []):
                script_blocks.append(
                    "<article class='script'><header>{}</header><pre>{}</pre></article>".format(
                        html.escape(f"{record.get('port', '')}/{record.get('protocol', '')}  •  {script.get('id', 'script')}"),
                        html.escape(str(script.get("output", "")))
                    )
                )
        if not script_blocks:
            script_blocks.append("<p class='empty'>No Nmap script output was returned for this scan.</p>")

        # Build the metadata rows (Target, MAC, OS, Distance).
        metadata = (("Target", data.get("target", "Unknown")),
                    ("MAC address", info.get("mac", "Unknown")),
                    ("Operating system", info.get("os", "Unknown")),
                    ("Network distance", info.get("distance", "Unknown")))
        meta_html = "".join(
            "<div class='meta'><span>{}</span><strong>{}</strong></div>".format(
                html.escape(label), html.escape(str(value))
            ) for label, value in metadata
        )

        # Assemble the final HTML document (f-string with CSS/JS embedded).
        return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>NIGHTHAWK 2.0.0 — Scan report</title>
<style>
:root {{ color-scheme: dark; --bg:#000000; --panel:#171717; --panel-2:#202020; --line:#353535; --text:#f5f7fa; --muted:#a6adb8; --primary:#3595F9; --green:#27AE60; --yellow:#FEDD0B; --orange:#F2994A; --red:#E05263; --maroon:#7A1E30; }}
* {{ box-sizing:border-box; }} body {{ margin:0; background:var(--bg); color:var(--text); font:14px/1.45 "Segoe UI",system-ui,sans-serif; }}
.topbar {{ display:flex; align-items:center; gap:14px; padding:16px max(24px,calc((100vw - 1500px)/2)); border-bottom:1px solid var(--line); background:#101010; color:var(--text); }}
.topbar .brand {{ color:var(--primary); }} .topbar .brand small {{ color:var(--muted); }} .mark {{ width:38px; height:38px; display:grid; place-items:center; overflow:hidden; }} .mark img {{ width:38px; height:38px; object-fit:contain; }}
.brand {{ font-weight:800; letter-spacing:.08em; }} .brand small {{ display:block; letter-spacing:.04em; font-size:10px; margin-top:2px; }}
.status {{ margin-left:auto; color:var(--primary); border:1px solid #245b98; padding:5px 9px; font-size:11px; font-weight:700; }}
main {{ max-width:1500px; margin:auto; padding:24px; }} h1 {{ font-size:24px; margin:0; }} .sub {{ margin:5px 0 20px; color:var(--muted); }}
.summary {{ display:grid; grid-template-columns:repeat(4,minmax(0,1fr)); gap:10px; margin-bottom:14px; }} .card,.panel {{ background:var(--panel); border:1px solid var(--line); }}
.card {{ padding:13px 15px; }} .card span {{ display:block; color:var(--muted); font-size:11px; text-transform:uppercase; letter-spacing:.06em; }} .card strong {{ display:block; margin-top:5px; font-size:21px; color:var(--primary); }} .card.good strong {{ color:var(--green); }} .card.warn strong {{ color:var(--yellow); }} .card.bad strong {{ color:var(--red); }}
.grid {{ display:grid; grid-template-columns:1.1fr 2fr; gap:14px; margin-bottom:14px; }} .panel-title {{ padding:13px 15px; border-bottom:1px solid var(--line); color:var(--text); font-weight:700; }}
.metadata {{ padding:8px 15px; }} .meta {{ display:grid; grid-template-columns:150px 1fr; gap:12px; padding:8px 0; border-bottom:1px solid #222b35; }} .meta:last-child {{ border:0; }} .meta span {{ color:var(--muted); }}
.risk {{ display:flex; align-items:center; gap:14px; padding:16px; }} .risk-badge {{ width:92px; height:92px; border-radius:50%; display:grid; place-items:center; text-align:center; border:8px solid currentColor; font-weight:800; font-size:14px; }} .risk-critical {{ color:var(--maroon); }} .risk-high {{ color:var(--red); }} .risk-review {{ color:var(--orange); }} .risk-exposed {{ color:var(--yellow); }} .risk-clear {{ color:var(--green); }} .risk p {{ color:var(--muted); margin:0; }}
.toolbar {{ display:flex; gap:8px; padding:14px; border-bottom:1px solid var(--line); }} button {{ border:1px solid #245b98; background:#1c4e83; color:#ffffff; padding:8px 11px; font:600 12px "Segoe UI",sans-serif; cursor:pointer; }} button:hover {{ background:#286cb4; }} input {{ margin-left:auto; min-width:260px; background:#101010; color:var(--text); border:1px solid var(--line); padding:8px 10px; }}
table {{ width:100%; border-collapse:collapse; }} th,td {{ padding:10px 14px; text-align:left; border-bottom:1px solid #2b2b2b; }} th {{ color:var(--muted); font-size:11px; letter-spacing:.05em; text-transform:uppercase; background:#202020; }} tr:hover td {{ background:#202020; }} .state-open {{ color:var(--green); font-weight:700; }} .state-other {{ color:var(--yellow); }}
.scripts {{ margin-top:14px; }} .script {{ margin:12px 14px; border:1px solid #303030; background:#101010; }} .script header {{ padding:8px 10px; color:var(--primary); border-bottom:1px solid #303030; font-weight:700; }} pre {{ margin:0; padding:12px; white-space:pre-wrap; overflow:auto; color:#dbe7f5; font:12px/1.45 ui-monospace,Consolas,monospace; }} .empty {{ color:var(--muted); padding:18px; text-align:center; }}
@media (max-width:850px) {{ main {{ padding:14px; }} .summary,.grid {{ grid-template-columns:1fr 1fr; }} .grid {{ display:block; }} .grid>.panel {{ margin-bottom:14px; }} input {{ min-width:0; width:100%; margin:0; }} .toolbar {{ flex-wrap:wrap; }} }}
</style>
</head>
<body>
<header class="topbar"><div class="mark"><img src="../logo.png" alt="Nighthawk"></div><div class="brand">NIGHTHAWK<small>ADVANCED NETWORK SCANNER · VERSION 2.0</small></div><div class="status">SCAN COMPLETE</div></header>
<main>
<h1>Scan report</h1><p class="sub">Target: {html.escape(str(data.get('target', 'Unknown')))} &nbsp;•&nbsp; Ports: {html.escape(str(data.get('ports', '')))} &nbsp;•&nbsp; {html.escape(str(data.get('created', '')).replace('T', ' ')[:19])}</p>
<section class="summary"><div class="card good"><span>Hosts up</span><strong>1</strong></div><div class="card"><span>Open ports</span><strong>{len(open_ports)}</strong></div><div class="card {'bad' if assessment['css'] in ('risk-critical', 'risk-high') else 'warn'}"><span>Script findings</span><strong>{len(scripts)}</strong></div><div class="card"><span>Ports scanned</span><strong>{html.escape(str(data.get('ports', '—')))}</strong></div></section>
<section class="grid"><div class="panel"><div class="panel-title">Target information</div><div class="metadata">{meta_html}</div></div><div class="panel"><div class="panel-title">Risk assessment</div><div class="risk {risk_class}"><div class="risk-badge">{risk}</div><p>{assessment['detail']}<br>{len(open_ports)} open port(s) · {len(scripts)} script finding(s)</p></div></div></section>
<section class="panel"><div class="panel-title">Ports &amp; services</div><div class="toolbar"><button onclick="downloadFile('json')">Export JSON</button><button onclick="downloadFile('csv')">Export CSV</button><button onclick="downloadFile('txt')">Export TXT</button><input id="filter" type="search" placeholder="Filter port, state, service, or version"></div><table id="results"><thead><tr><th>Port</th><th>State</th><th>Service</th><th>Version</th><th>Reason</th></tr></thead><tbody>{''.join(rows)}</tbody></table></section>
<section class="panel scripts"><div class="panel-title">Script output</div>{''.join(script_blocks)}</section>
</main>
<script>
const reportData = {{json:{json.dumps(data)},csv:{json.dumps(base.with_suffix('.csv').read_text(encoding='utf-8'))},txt:{json.dumps(base.with_suffix('.txt').read_text(encoding='utf-8'))}}};
function downloadFile(ext) {{ const blob=new Blob([typeof reportData[ext] === 'string' ? reportData[ext] : JSON.stringify(reportData[ext],null,2)],{{type:'text/plain'}}); const url=URL.createObjectURL(blob); const link=document.createElement('a'); link.href=url; link.download='{base.name}.'+ext; link.click(); URL.revokeObjectURL(url); }}
document.getElementById('filter').addEventListener('input', function() {{ const q=this.value.toLowerCase(); document.querySelectorAll('#results tbody tr').forEach(row => row.hidden=!row.textContent.toLowerCase().includes(q)); }});
</script></body></html>"""

    # =======================================================================
    # VERSION 2 HISTORY (OVERRIDES THE LEGACY ONE)
    # Opens a two-panel window:
    #   Left  — list of all saved JSON reports (selectable, Ctrl-click for two).
    #   Right — a "diff" text view showing what ports changed between two scans.
    # =======================================================================
    def show_history(self):
        """Open the active Version 2 history window and compare two saved JSON reports."""
        folder = Path(__file__).with_name("reports")
        files = sorted(folder.glob("*.json"), reverse=True) if folder.exists() else []
        if not files:
            messagebox.showinfo("Scan history", "No completed scan reports are available yet.")
            return

        win = tk.Toplevel(self.root)
        win.title("NIGHTHAWK — Scan history")
        win.geometry("1120x690")
        win.minsize(900, 540)
        win.configure(bg=self.BG)
        win.grid_rowconfigure(1, weight=1)
        win.grid_columnconfigure(0, weight=1)

        # Header block.
        header = tk.Frame(win, bg=self.BG)
        header.grid(row=0, column=0, sticky="ew", padx=18, pady=(16, 10))
        tk.Label(header, text="Scan history", bg=self.BG, fg=self.FG, font=("Segoe UI", 18, "bold")).pack(anchor="w")
        tk.Label(header, text="Select two reports to compare. Double-click one report to open its HTML view.", bg=self.BG, fg=self.MUTED, font=("Segoe UI", 10)).pack(anchor="w", pady=(2, 0))

        # Two-panel layout (adjustable divider).
        workspace = tk.PanedWindow(win, orient=tk.HORIZONTAL, sashwidth=5, bg=self.BG, bd=0, sashrelief=tk.FLAT)
        workspace.grid(row=1, column=0, sticky="nsew", padx=18, pady=(0, 12))
        left = tk.Frame(workspace, bg=self.PANEL, highlightbackground="#914187", highlightthickness=1)
        right = tk.Frame(workspace, bg=self.PANEL, highlightbackground="#914187", highlightthickness=1)
        workspace.add(left, minsize=410)
        workspace.add(right, minsize=390)

        # --- LEFT: report list as a Treeview -----------------------------
        tk.Label(left, text="Completed scans", bg=self.PANEL, fg=self.FG, font=("Segoe UI", 11, "bold")).pack(anchor="w", padx=14, pady=(12, 7))
        columns = ("date", "target", "ports", "open")
        history = ttk.Treeview(left, columns=columns, show="headings", selectmode="extended", style="Nighthawk.Treeview")
        for key, heading, width in (("date", "DATE", 145), ("target", "TARGET", 135), ("ports", "PORTS", 100), ("open", "OPEN", 55)):
            history.heading(key, text=heading)
            history.column(key, width=width, anchor="w")
        history.pack(fill=tk.BOTH, expand=True, padx=12, pady=(0, 12))

        # Map Treeview item IDs → actual file paths.
        report_files = {}
        for report in files:
            try:
                payload = json.loads(report.read_text(encoding="utf-8"))
                created = payload.get("created", "").replace("T", " ")[:16] or report.stem
                open_count = sum(1 for item in payload.get("results", []) if item.get("state") == "open")
                item_id = history.insert("", tk.END, values=(created, payload.get("target", "—"), payload.get("ports", "—"), open_count))
                report_files[item_id] = report
            except (OSError, ValueError, json.JSONDecodeError):
                # Corrupted file — show it but without metadata.
                item_id = history.insert("", tk.END, values=(report.stem, "—", "—", "—"))
                report_files[item_id] = report

        # --- RIGHT: diff view --------------------------------------------
        tk.Label(right, text="Comparison", bg=self.PANEL, fg=self.FG, font=("Segoe UI", 11, "bold")).pack(anchor="w", padx=14, pady=(12, 7))
        diff = scrolledtext.ScrolledText(right, state=tk.DISABLED, bg="#240018", fg=self.FG, insertbackground=self.ACCENT,
                                         relief=tk.FLAT, font=("Cascadia Mono", 10), padx=14, pady=12)
        diff.pack(fill=tk.BOTH, expand=True, padx=12, pady=(0, 12))
        diff.tag_config("added", foreground="#3ddc97")
        diff.tag_config("removed", foreground=self.ERROR)
        diff.tag_config("heading", foreground="#f2c8ed", font=("Cascadia Mono", 10, "bold"))
        diff.tag_config("muted", foreground=self.MUTED)

        # --- BOTTOM: actions ---------------------------------------------
        actions = tk.Frame(win, bg=self.BG)
        actions.grid(row=2, column=0, sticky="ew", padx=18, pady=(0, 16))
        selection_note = tk.StringVar(value="Choose two reports to compare their open ports.")
        tk.Label(actions, textvariable=selection_note, bg=self.BG, fg=self.MUTED, font=("Segoe UI", 9)).pack(side=tk.LEFT)

        def selected_reports():
            """Return the file paths for every currently selected row."""
            ids = history.selection()
            return [report_files[item] for item in ids if item in report_files]

        def write_diff():
            """Diff the two selected reports (added/removed open ports)."""
            chosen = selected_reports()
            if len(chosen) != 2:
                selection_note.set("Select exactly two reports to compare.")
                return
            try:
                older, newer = (json.loads(path.read_text(encoding="utf-8")) for path in chosen)
                # Key by (protocol, port) so TCP/80 and UDP/80 stay distinct.
                old_ports = {(item.get("protocol"), item.get("port")): item for item in older.get("results", []) if item.get("state") == "open"}
                new_ports = {(item.get("protocol"), item.get("port")): item for item in newer.get("results", []) if item.get("state") == "open"}
                added = sorted(set(new_ports) - set(old_ports))
                removed = sorted(set(old_ports) - set(new_ports))

                diff.config(state=tk.NORMAL)
                diff.delete("1.0", tk.END)
                diff.insert(tk.END, "REPORT COMPARISON\n", "heading")
                diff.insert(tk.END, f"Older: {older.get('target', '—')}  |  Newer: {newer.get('target', '—')}\n\n", "muted")

                if added:
                    diff.insert(tk.END, "NEWLY OPEN PORTS\n", "heading")
                    for protocol, port in added:
                        record = new_ports[(protocol, port)]
                        diff.insert(tk.END, f"+ {port}/{protocol}  {record.get('service', 'unknown')}\n", "added")
                    diff.insert(tk.END, "\n")

                if removed:
                    diff.insert(tk.END, "NO LONGER OPEN\n", "heading")
                    for protocol, port in removed:
                        record = old_ports[(protocol, port)]
                        diff.insert(tk.END, f"- {port}/{protocol}  {record.get('service', 'unknown')}\n", "removed")

                if not added and not removed:
                    diff.insert(tk.END, "No open-port changes were found.", "muted")

                diff.config(state=tk.DISABLED)
                selection_note.set(f"Compared {chosen[0].name} with {chosen[1].name}.")
            except (OSError, ValueError, json.JSONDecodeError) as error:
                messagebox.showerror("Comparison failed", str(error), parent=win)

        def open_selected(_event=None):
            """Open the HTML report of the first selected row."""
            chosen = selected_reports()
            if chosen:
                report = chosen[0].with_suffix(".html")
                if report.exists():
                    webbrowser.open(report.as_uri())

        history.bind("<Double-1>", open_selected)
        tk.Button(actions, text="OPEN REPORT", command=open_selected, bg="#3d1231", fg=self.FG, relief=tk.FLAT, font=("Segoe UI", 9, "bold"), padx=13, pady=8).pack(side=tk.RIGHT, padx=(8, 0))
        tk.Button(actions, text="COMPARE SELECTED", command=write_diff, bg=self.ACCENT, fg="white", relief=tk.FLAT, font=("Segoe UI", 9, "bold"), padx=13, pady=8).pack(side=tk.RIGHT)


# ---------------------------------------------------------------------------
# PROGRAM ENTRY POINT
# When run as a script (not imported), handle --help / --version, then
# create the main Tk window and start the event loop.
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    # --- Handle command-line arguments -------------------------------
    if "--help" in sys.argv[1:] or "-h" in sys.argv[1:]:
        print("""NIGHTHAWK 2.0.0 - Advanced Network Scanner\n\nUsage: ./scanner.py [OPTIONS]\n\nOptions:\n  -h, --help       Show this help message and exit\n  -V, --version    Show version information and exit\n\nRequirements:\n  Python 3.9 or newer with Tkinter, and Nmap on PATH.\n  Run ./requirements.txt to check or install Linux prerequisites.\n\nReports:\n  Completed scans are written to ./reports/ as HTML, JSON, CSV, and TXT files.\n\nOnly scan hosts you own or have permission to test.""")
        sys.exit(0)

    if "--version" in sys.argv[1:] or "-V" in sys.argv[1:]:
        print("NIGHTHAWK 2.0.0")
        sys.exit(0)

    # --- Create the window and run the app ---------------------------
    root = tk.Tk()           # The root (main) Tkinter window.
    NighthawkApp(root)       # Instantiate the app — builds all widgets.
    root.mainloop()          # Hand control to Tkinter's event loop (blocks).