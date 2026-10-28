import csv
import datetime
import html
import json
import os
import re
import shlex
import shutil
import subprocess
import tempfile
import threading
import tkinter as tk
import uuid
import webbrowser
import xml.etree.ElementTree as ET
from pathlib import Path
from tkinter import messagebox, scrolledtext, ttk, simpledialog


class NighthawkApp:
    # Color Palette
    BG = "#091017"
    PANEL = "#111e29"
    FG = "#b8f7d4"
    MUTED = "#7da18f"
    ACCENT = "#20e08a"
    WARN = "#ffcc66"
    ERROR = "#ff6b6b"
    
    MAX_TARGET_LENGTH = 253
    MAX_PORT_EXPRESSION_LENGTH = 256
    MAX_CUSTOM_FLAGS_LENGTH = 2048
    MAX_REPORT_XML_BYTES = 25 * 1024 * 1024
    
    BLOCKED_CUSTOM_FLAGS = {
        "-il", "-ir", "--datadir", "--stylesheet", "--webxml",
        "--resume", "--append-output", "-on", "-ox", "-og", "-oa",
    }

    # Comprehensive Scan Types & Bypass Techniques
    SCAN_TYPES = {
        # Basic Scans
        "TCP Connect (-sT)": ("-sT", "Completes a TCP connection; works without admin."),
        "TCP SYN (-sS)": ("-sS", "Half-open TCP scan; usually requires admin."),
        "UDP Scan (-sU)": ("-sU", "Probes UDP services; slower, requires admin."),
        "FIN Scan (-sF)": ("-sF", "Sends FIN packets to bypass simple firewalls."),
        "Xmas Scan (-sX)": ("-sX", "Sends FIN, PSH, and URG flags."),
        "NULL Scan (-sN)": ("-sN", "Sends TCP packets without flags."),
        "ACK Scan (-sA)": ("-sA", "Maps firewall rules."),
        "Window Scan (-sW)": ("-sW", "TCP window scan."),
        "Maimon Scan (-sM)": ("-sM", "TCP Maimon scan."),
        
        # Discovery & Protocol
        "Ping Discovery (-sn)": ("-sn", "Discovers online hosts without port scanning."),
        "IP Protocol (-sO)": ("-sO", "Scans IP protocols instead of ports."),
        
        # Firewall / IDS Evasion
        "--- FIREWALL / IDS BYPASS ---": (None, None), # Separator
        "Fragment Packets (-f)": ("-f", "Fragments packets to bypass simple firewalls."),
        "Custom MTU (--mtu 24)": ("--mtu 24", "Sets a specific packet size to confuse firewalls."),
        "Decoy Scan (-D RND:10)": ("-D RND:10", "Cloaks scan with 10 random decoys."),
        "Spoof MAC (--spoof-mac 0)": ("--spoof-mac 0", "Generates a random MAC address."),
        "Bad Checksum (--badsum)": ("--badsum", "Sends packets with bad checksums to identify firewalls."),
        "Idle Scan (-sI)": ("-sI", "Advanced blind scan using a zombie host."),
        "Source Port Spoof (-g 53)": ("-g 53", "Uses a specific source port (like DNS 53) to bypass rules."),
        
        # Custom
        "--- CUSTOM ---": (None, None), # Separator
        "Custom Flags": (None, "Use your own scanner flags."),
    }

    TIMING_TEMPLATES = {
        "Insane (T5)": "-T5",
        "Aggressive (T4)": "-T4",
        "Normal (T3)": "-T3",
        "Polite (T2)": "-T2",
        "Sneaky (T1)": "-T1",
        "Paranoid (T0)": "-T0",
    }

    PROFILES = {
        "Custom / Manual": None,
        "Quick TCP (Top 100)": {"type": "TCP Connect (-sT)", "ports": "Top 100", "service": True, "os": False, "timing": "Insane (T5)"},
        "Intense Scan (All)": {"type": "TCP Connect (-sT)", "ports": "All", "service": True, "os": True, "timing": "Aggressive (T4)"},
        "Stealth SYN (Root)": {"type": "TCP SYN (-sS)", "ports": "1-1024", "service": True, "os": False, "timing": "Sneaky (T1)"},
        "Evade Firewall": {"type": "Fragment Packets (-f)", "ports": "1-1024", "service": True, "os": False, "timing": "Polite (T2)"},
        "Ping Sweep": {"type": "Ping Discovery (-sn)", "ports": "N/A", "service": False, "os": False, "timing": "Normal (T3)"},
    }

    CONFIG_FILE = Path(__file__).with_name("nighthawk_config.json")

    def __init__(self, root):
        self.root = root
        self.root.title("NIGHTHAWK // Advanced Network Scanner")
        self.root.geometry("1150x850")
        self.root.minsize(1000, 750)
        self.root.configure(bg=self.BG)
        
        self.is_scanning = False
        self.scan_process = None
        self.last_report = None
        self.current_xml_path = None
        self.live_host_info = {"mac": "Scanning...", "os": "Scanning..."}
        
        self.config = self.load_config()
        self.build_ui()

    def load_config(self):
        if self.CONFIG_FILE.exists():
            try:
                return json.loads(self.CONFIG_FILE.read_text(encoding="utf-8"))
            except Exception:
                pass
        return {}

    def save_config(self):
        try:
            self.CONFIG_FILE.write_text(json.dumps(self.config, indent=2), encoding="utf-8")
        except Exception:
            pass

    def build_ui(self):
        # --- HEADER ---
        header = tk.Frame(self.root, bg=self.BG, padx=18, pady=14)
        header.pack(fill=tk.X)
        tk.Label(header, text="NIGHTHAWK", font=("Consolas", 24, "bold"),
                 fg=self.ACCENT, bg=self.BG).pack(side=tk.LEFT)
        tk.Label(header, text="  //  ADVANCED NETWORK RECON",
                 font=("Consolas", 10), fg=self.MUTED, bg=self.BG).pack(side=tk.LEFT, pady=(9, 0))
        
        tk.Button(header, text="? CHEATSHEET", command=self.show_cheatsheet, 
                  bg=self.PANEL, fg=self.ACCENT, font=("Consolas", 9, "bold"), 
                  relief=tk.FLAT, padx=10, cursor="hand2").pack(side=tk.RIGHT, padx=10)
        
        self.auto_open_var = tk.BooleanVar(value=self.config.get("auto_open", True))
        self.option(header, "AUTO-OPEN", self.auto_open_var).pack(side=tk.RIGHT, padx=10)

        # --- CONFIG PANEL ---
        panel = tk.Frame(self.root, bg=self.PANEL, padx=14, pady=12)
        panel.pack(fill=tk.X, padx=14)
        
        self.add_label(panel, "PROFILE").grid(row=0, column=0, sticky="w")
        self.profile_var = tk.StringVar(value=self.config.get("profile", "Custom / Manual"))
        self.profile_menu = tk.OptionMenu(panel, self.profile_var, *self.PROFILES, command=self.apply_profile)
        self.style_menu(self.profile_menu)
        self.profile_menu.grid(row=1, column=0, padx=(0, 12), sticky="ew")

        self.add_label(panel, "TARGET (IP or CIDR)").grid(row=0, column=1, sticky="w")
        self.target_entry = self.add_entry(panel, self.config.get("target", "127.0.0.1"), 25)
        self.target_entry.grid(row=1, column=1, padx=(0, 12), sticky="ew")

        self.add_label(panel, "PORTS").grid(row=0, column=2, sticky="w")
        port_frame = tk.Frame(panel, bg=self.PANEL)
        port_frame.grid(row=1, column=2, padx=(0, 12), sticky="ew")
        self.port_entry = self.add_entry(port_frame, self.config.get("ports", "1-1024"), 12)
        self.port_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        self.port_dropdown = tk.StringVar(value="Custom")
        port_menu = tk.OptionMenu(port_frame, self.port_dropdown, "Custom", "Top 100", "Top 1000", "All", command=self.apply_port_preset)
        self.style_menu(port_menu)
        port_menu.pack(side=tk.LEFT, padx=(5, 0))

        self.add_label(panel, "SCAN TYPE").grid(row=0, column=3, sticky="w")
        self.scan_type = tk.StringVar(value=self.config.get("scan_type", "TCP Connect (-sT)"))
        
        # Custom OptionMenu to handle the separators in SCAN_TYPES
        self.scan_menu = tk.OptionMenu(panel, self.scan_type, *self.SCAN_TYPES, command=self.scan_type_changed)
        self.style_menu(self.scan_menu)
        # Inject separators into the menu
        menu = self.scan_menu["menu"]
        menu.delete(0, "end")
        for key in self.SCAN_TYPES:
            if key.startswith("---"):
                menu.add_separator()
            else:
                menu.add_command(label=key, command=lambda v=key: self._set_scan_type(v))
                
        self.scan_menu.grid(row=1, column=3, padx=(0, 12), sticky="ew")

        self.add_label(panel, "TIMING").grid(row=0, column=4, sticky="w")
        self.timing_var = tk.StringVar(value=self.config.get("timing", "Insane (T5)"))
        self.timing_menu = tk.OptionMenu(panel, self.timing_var, *self.TIMING_TEMPLATES)
        self.style_menu(self.timing_menu)
        self.timing_menu.grid(row=1, column=4, padx=(0, 12), sticky="ew")
        
        panel.grid_columnconfigure(0, weight=1)
        panel.grid_columnconfigure(1, weight=3)
        panel.grid_columnconfigure(2, weight=2)
        panel.grid_columnconfigure(3, weight=2)
        panel.grid_columnconfigure(4, weight=2)

        # --- OPTIONS & NSE ---
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

        # --- FAVORITES & EXTRA FLAGS ---
        extra_frame = tk.Frame(self.root, bg=self.BG, padx=16, pady=0)
        extra_frame.pack(fill=tk.X)
        self.add_label(extra_frame, "EXTRA FLAGS").pack(side=tk.LEFT)
        self.extra_entry = self.add_entry(extra_frame, self.config.get("extra_flags", "--reason"), 40)
        self.extra_entry.pack(side=tk.LEFT, padx=6, fill=tk.X, expand=True)
        
        self.save_fav_btn = self.button(extra_frame, "SAVE PRESET", self.save_favorite, "#19364a", self.MUTED)
        self.save_fav_btn.pack(side=tk.LEFT, padx=(6, 0))

        # --- CUSTOM MODE ---
        self.custom_frame = tk.Frame(self.root, bg="#172b28", padx=16, pady=10)
        self.add_label(self.custom_frame, "CUSTOM COMMAND").pack(side=tk.LEFT)
        self.custom_entry = self.add_entry(self.custom_frame, "-sT -sV --reason", 55)
        self.custom_entry.pack(side=tk.LEFT, padx=8, fill=tk.X, expand=True)
        self.custom_frame.pack_forget()
        self.entries = {"TARGET": self.target_entry}

        # --- COMMAND PREVIEW ---
        command = tk.Frame(self.root, bg=self.BG, padx=16, pady=8)
        command.pack(fill=tk.X)
        self.add_label(command, "COMMAND RUN").pack(side=tk.LEFT)
        self.command_var = tk.StringVar(value="Waiting for scan configuration...")
        tk.Entry(command, textvariable=self.command_var, state="readonly",
                 readonlybackground="#05090c", fg=self.ACCENT, relief=tk.FLAT,
                 font=("Consolas", 9)).pack(side=tk.LEFT, padx=10, fill=tk.X, expand=True)

        # --- CONTROLS & LIVE INFO ---
        controls = tk.Frame(self.root, bg=self.BG, padx=14, pady=10)
        controls.pack(fill=tk.X)
        
        self.start_btn = self.button(controls, "▶  LAUNCH", self.start_scan, "#123b2b", self.ACCENT)
        self.start_btn.pack(side=tk.LEFT)
        
        self.stop_btn = self.button(controls, "■  ABORT", self.stop_scan, "#3b1b20", self.ERROR)
        self.stop_btn.config(state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=8)
        
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
        
        self.live_info_label = tk.Label(controls, text="MAC: --- | OS: ---", 
                                        fg=self.WARN, bg=self.BG, font=("Consolas", 9, "bold"))
        self.live_info_label.pack(side=tk.LEFT, padx=15)
        
        self.status_label = tk.Label(controls, text="READY", fg=self.MUTED, bg=self.BG, font=("Consolas", 10))
        self.status_label.pack(side=tk.RIGHT)

        # --- TERMINAL OUTPUT ---
        self.output = scrolledtext.ScrolledText(self.root, state=tk.DISABLED, bg="#05090c",
                                                fg=self.FG, insertbackground=self.ACCENT,
                                                font=("Consolas", 10), relief=tk.FLAT, padx=10, pady=10)
        self.output.pack(fill=tk.BOTH, expand=True, padx=16, pady=(4, 10))
        
        self.output.tag_config("open", foreground="#20e08a")
        self.output.tag_config("closed", foreground="#ff6b6b")
        self.output.tag_config("error", foreground="#ffcc66")

        # --- FOOTER REPORTS ---
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

    def _set_scan_type(self, value):
        self.scan_type.set(value)
        self.scan_type_changed(value)

    def show_cheatsheet(self):
        win = tk.Toplevel(self.root)
        win.title("Nmap Cheatsheet")
        win.geometry("900x700")
        win.configure(bg=self.BG)
        
        text = scrolledtext.ScrolledText(win, bg="#05090c", fg=self.FG, font=("Consolas", 10), padx=15, pady=15)
        text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
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
        text.config(state=tk.DISABLED)

    def apply_profile(self, profile_name):
        profile = self.PROFILES.get(profile_name)
        if not profile: return
        self._set_scan_type(profile["type"])
        self.timing_var.set(profile["timing"])
        self.port_dropdown.set(profile["ports"])
        self.apply_port_preset(profile["ports"])
        self.service_var.set(profile["service"])
        self.os_var.set(profile["os"])

    def apply_port_preset(self, preset):
        self.port_entry.delete(0, tk.END)
        if preset == "Top 100":
            self.port_entry.insert(0, "--top-ports 100")
        elif preset == "Top 1000":
            self.port_entry.insert(0, "--top-ports 1000")
        elif preset == "All":
            self.port_entry.insert(0, "1-65535")
        else:
            self.port_entry.insert(0, "1-1024")

    def save_favorite(self):
        name = simpledialog.askstring("Save Preset", "Enter a name for this scan preset:", parent=self.root)
        if not name: return
        
        if "favorites" not in self.config:
            self.config["favorites"] = {}
            
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
        
        if name not in self.PROFILES:
            self.PROFILES[name] = "favorite"
            self.profile_menu["menu"].add_command(label=name, command=lambda v=name: self.profile_var.set(v) or self.apply_favorite(v))
        messagebox.showinfo("Saved", f"Preset '{name}' saved.")

    def apply_favorite(self, name):
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

    def add_label(self, parent, text):
        frame = tk.Frame(parent, bg=parent.cget("bg"))
        tk.Label(frame, text=text, fg=self.MUTED, bg=parent.cget("bg"),
                 font=("Consolas", 8, "bold")).pack(side=tk.LEFT)
        return frame

    def add_entry(self, parent, value, width):
        entry = tk.Entry(parent, width=width, bg="#192936", fg=self.FG,
                         insertbackground=self.ACCENT, relief=tk.FLAT, font=("Consolas", 10))
        entry.insert(0, value)
        return entry

    def option(self, parent, text, variable):
        return tk.Checkbutton(parent, text=text, variable=variable, fg=self.FG, bg=parent.cget("bg"),
                               selectcolor=self.PANEL, activebackground=self.BG, activeforeground=self.ACCENT,
                               font=("Consolas", 9), relief=tk.FLAT)

    def style_menu(self, menu):
        menu.config(bg="#192936", fg=self.FG, activebackground="#223d4c",
                    activeforeground=self.ACCENT, highlightthickness=0, width=24)
        menu["menu"].config(bg="#192936", fg=self.FG)

    def button(self, parent, text, command, background, foreground):
        width = len(text) + 2
        return tk.Button(parent, text=text, command=command, bg=background, fg=foreground,
                         activebackground="#28536a", activeforeground="white",
                         font=("Consolas", 9, "bold"), relief=tk.FLAT,
                         width=width, padx=6, pady=7)

    def log(self, text):
        self.output.config(state=tk.NORMAL)
        if "open" in text.lower():
            self.output.insert(tk.END, text + "\n", ("open",))
        elif "closed" in text.lower() or "filtered" in text.lower():
            self.output.insert(tk.END, text + "\n", ("closed",))
        elif "error" in text.lower() or "fail" in text.lower():
            self.output.insert(tk.END, text + "\n", ("error",))
        else:
            self.output.insert(tk.END, text + "\n")
        self.output.see(tk.END)
        self.output.config(state=tk.DISABLED)

    def update_live_info(self, text):
        mac_match = re.search(r"MAC Address: ([0-9A-F:]+) \(([^)]+)\)", text)
        if mac_match:
            self.live_host_info["mac"] = f"{mac_match.group(1)} ({mac_match.group(2)})"
        
        os_match = re.search(r"OS details: (.*)", text)
        if os_match:
            self.live_host_info["os"] = os_match.group(1)
            
        self.live_info_label.config(text=f"MAC: {self.live_host_info['mac']} | OS: {self.live_host_info['os']}")

    def update_ui(self, callback, *args, **kwargs):
        self.root.after(0, lambda: callback(*args, **kwargs))

    def scan_type_changed(self, selected):
        # Hide standard options if Custom OR Evasion type is selected
        custom_types = [
            "Custom Flags", "Fragment Packets (-f)", "Custom MTU (--mtu 24)", 
            "Decoy Scan (-D RND:10)", "Spoof MAC (--spoof-mac 0)", 
            "Bad Checksum (--badsum)", "Idle Scan (-sI)", "Source Port Spoof (-g 53)"
        ]
        
        if selected in custom_types:
            self.options_frame.pack_forget()
            if selected == "Custom Flags":
                self.custom_frame.pack(fill=tk.X, before=self.output)
            else:
                self.custom_frame.pack_forget()
        else:
            self.custom_frame.pack_forget()
            self.options_frame.pack(fill=tk.X, before=self.output)

    def start_scan(self):
        host = self.target_entry.get().strip()
        ports = self.port_entry.get().strip()
        engine = shutil.which("nmap")
        
        self.config["target"] = host
        self.config["ports"] = ports
        self.config["scan_type"] = self.scan_type.get()
        self.config["timing"] = self.timing_var.get()
        self.config["service"] = self.service_var.get()
        self.config["os"] = self.os_var.get()
        self.config["extra_flags"] = self.extra_entry.get()
        self.config["auto_open"] = self.auto_open_var.get()
        self.save_config()

        if not host or not ports:
            messagebox.showerror("NIGHTHAWK", "Target and port expression are required.")
            return
        if engine is None:
            messagebox.showerror("NIGHTHAWK", "Nmap not found. Install it and add it to PATH.")
            return
            
        if "/" in host:
            self.run_subnet_sweep(host, engine)
            return

        if not self.valid_ports(ports) and ports != "N/A" and not ports.startswith("--top-ports"):
            messagebox.showerror("NIGHTHAWK", "Use ports like 443, 1-1024, 22,80,443, or --top-ports 100.")
            return
            
        try:
            flags_text = self.custom_entry.get() if self.scan_type.get() == "Custom Flags" else self.extra_entry.get()
            flags = self.parse_flags(flags_text)
        except ValueError as error:
            messagebox.showerror("NIGHTHAWK", f"Invalid custom flags: {error}")
            return
            
        if self.scan_type.get() == "Custom Flags" and not flags:
            messagebox.showerror("NIGHTHAWK", "Enter custom scanner flags.")
            return
        
        command = [engine]
        if self.scan_type.get() == "Custom Flags":
            command.extend(flags)
        else:
            # Get the base flag (e.g., -sT or -f)
            base_flag = self.SCAN_TYPES[self.scan_type.get()][0]
            if base_flag:
                command.append(base_flag)
                
            command.append(self.TIMING_TEMPLATES[self.timing_var.get()])
            
            # Only add -sV and -O if not using a specific stealth scan (unless user overrides)
            evasion_types = [
                "Fragment Packets (-f)", "Custom MTU (--mtu 24)", 
                "Decoy Scan (-D RND:10)", "Spoof MAC (--spoof-mac 0)", 
                "Bad Checksum (--badsum)", "Idle Scan (-sI)", "Source Port Spoof (-g 53)"
            ]
            
            if self.service_var.get() and self.scan_type.get() not in ("Ping Discovery (-sn)", "IP Protocol (-sO)") and self.scan_type.get() not in evasion_types:
                command.append("-sV")
            if self.os_var.get() and self.scan_type.get() not in ("Ping Discovery (-sn)", "IP Protocol (-sO)") and self.scan_type.get() not in evasion_types:
                command.append("-O")
            
            if self.nse_default.get(): command.append("-sC")
            if self.nse_vuln.get(): command.extend(["--script", "vuln"])
            if self.nse_http.get(): command.extend(["--script", "http-enum"])
            if self.nse_ssl.get(): command.extend(["--script", "ssl-enum-ciphers"])
                
            command.extend(flags)
            
        self.current_xml_path = Path(self.xml_path())
        
        if ports != "N/A":
            if ports.startswith("--top-ports"):
                command.extend(ports.split())
            else:
                command.extend(["-p", ports])
                
        command.extend(["-oX", str(self.current_xml_path), host])
        self._execute_command(command, host, ports)

    def _execute_command(self, command, host, ports):
        self.command_var.set(self.display_command(command))
        self.clear_output()
        self.is_scanning = True
        self.live_host_info = {"mac": "Scanning...", "os": "Scanning..."}
        self.update_ui(self.live_info_label.config, text="MAC: --- | OS: ---")
        
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.progress.start(10)
        self.status_label.config(text="RUNNING // REPORT CAPTURE ACTIVE", fg=self.ACCENT)
        threading.Thread(target=self.run_scan, args=(command, host, ports), daemon=True).start()

    def run_subnet_sweep(self, subnet, engine):
        self.clear_output()
        self.is_scanning = True
        self.start_btn.config(state=tk.DISABLED)
        self.status_label.config(text="DISCOVERING HOSTS...", fg=self.WARN)
        self.progress.start(10)
        self.update_ui(self.log, f"[*] Running Ping Sweep on {subnet}...")
        
        def sweep():
            command = [engine, "-sn", "-T4", subnet]
            try:
                flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
                proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, creationflags=flags)
                out, _ = proc.communicate()
                
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

    def show_subnet_results(self, ips):
        self.finish_scan("READY")
        win = tk.Toplevel(self.root)
        win.title("Live Hosts Found")
        win.geometry("400x500")
        win.configure(bg=self.BG)
        
        tk.Label(win, text="Select targets to scan:", bg=self.BG, fg=self.ACCENT, font=("Consolas", 10, "bold")).pack(pady=10)
        
        frame = tk.Frame(win, bg=self.BG)
        frame.pack(fill=tk.BOTH, expand=True, padx=20)
        
        vars = []
        for ip in ips:
            var = tk.BooleanVar(value=True)
            chk = tk.Checkbutton(frame, text=ip, variable=var, fg=self.FG, bg=self.BG, selectcolor=self.PANEL, font=("Consolas", 10))
            chk.pack(anchor="w")
            vars.append((ip, var))
            
        def scan_selected():
            selected = [ip for ip, var in vars if var.get()]
            if not selected:
                messagebox.showwarning("Empty", "Select at least one host.")
                return
            win.destroy()
            self.target_entry.delete(0, tk.END)
            self.target_entry.insert(0, ",".join(selected))
            self.start_scan()
            
        tk.Button(win, text="SCAN SELECTED", command=scan_selected, bg="#19364a", fg=self.ACCENT, font=("Consolas", 10, "bold"), pady=5).pack(fill=tk.X, padx=20, pady=10)

    @staticmethod
    def valid_ports(expression):
        if not expression: return False
        if expression.startswith("--top-ports"): return True
        if len(expression) > NighthawkApp.MAX_PORT_EXPRESSION_LENGTH: return False
        try:
            for part in expression.split(","):
                part = part.strip()
                if not part: return False
                if "-" in part:
                    start, end = (int(value) for value in part.split("-", 1))
                    if not 1 <= start <= end <= 65535: return False
                elif not 1 <= int(part) <= 65535: return False
            return bool(expression)
        except ValueError:
            return False

    @classmethod
    def parse_flags(cls, text):
        if len(text) > cls.MAX_CUSTOM_FLAGS_LENGTH:
            raise ValueError("custom flags are too long")
        flags = shlex.split(text, posix=False)
        for flag in flags:
            option = flag.split("=", 1)[0].casefold()
            if option in cls.BLOCKED_CUSTOM_FLAGS or option.startswith(("-on", "-ox", "-og", "-oa", "-il", "-ir")):
                raise ValueError(f"{flag} is reserved.")
        return flags

    def xml_path(self):
        handle, path = tempfile.mkstemp(suffix=".xml", prefix="nighthawk_")
        os.close(handle)
        return path

    def run_scan(self, command, host, ports):
        self.update_ui(self.log, "$ " + self.display_command(command))
        try:
            flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
            self.scan_process = subprocess.Popen(command, stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT, text=True, encoding="utf-8", errors="replace", creationflags=flags)
            for line in self.scan_process.stdout:
                if not self.is_scanning:
                    continue
                stripped = line.strip()
                
                self.update_ui(self.update_live_info, line)
                
                if (stripped.startswith("Starting Nmap")
                        or stripped.startswith("Nmap done")
                        or stripped.startswith("Nmap scan report for")):
                    continue
                self.update_ui(self.log, line.rstrip())
            code = self.scan_process.wait()
        except OSError as error:
            self.update_ui(self.log, f"[ERROR] Could not start scanner: {error}")
            code = 1
        self.scan_process = None
        if self.is_scanning and code == 0:
            self.update_ui(self.create_reports, host, ports)
        elif self.is_scanning:
            if self.current_xml_path is not None:
                self.current_xml_path.unlink(missing_ok=True)
            self.update_ui(self.finish_scan, f"EXIT CODE {code}")
        elif self.current_xml_path is not None:
            self.current_xml_path.unlink(missing_ok=True)

    def create_reports(self, host, ports):
        try:
            if self.current_xml_path is None:
                raise OSError("No report data path was created")
            xml_file = self.current_xml_path
            root = ET.parse(xml_file).getroot()
            records = []
            
            has_os_info = False
            has_mac_info = False
            has_uptime = False
            has_distance = False
            has_service_info = False
            has_version = False
            has_scripts = False
            
            host_info = {
                "os": "Unknown", "mac": "Unknown", "vendor": "Unknown", 
                "device": "Unknown", "uptime": "Unknown", "distance": "Unknown", "service_info": "Unknown"
            }
            
            for host_node in root.findall("host"):
                for address in host_node.findall("address"):
                    if address.get("addrtype") == "mac":
                        host_info["mac"] = address.get("addr", "Unknown")
                        host_info["vendor"] = address.get("vendor", "Unknown")
                        has_mac_info = True
                
                os_node = host_node.find("os")
                if os_node is not None:
                    os_match = os_node.find("osmatch")
                    if os_match is not None:
                        host_info["os"] = os_match.get("name", "Unknown")
                        os_class = os_match.find("osclass")
                        if os_class is not None:
                            host_info["device"] = os_class.get("type", "Unknown")
                        has_os_info = True
                
                uptime_node = host_node.find("uptime")
                if uptime_node is not None:
                    host_info["uptime"] = f"{uptime_node.get('seconds')}s"
                    has_uptime = True
                
                distance_node = host_node.find("distance")
                if distance_node is not None:
                    host_info["distance"] = f"{distance_node.get('value')} hops"
                    has_distance = True

                hostscript = host_node.find("hostscript")
                if hostscript is not None:
                    for script in hostscript.findall("script"):
                        if script.get("id") == "smb-os-discovery":
                            host_info["service_info"] = script.get("output", "").replace("\n", " | ")
                            has_service_info = True

                for port_node in host_node.findall("./ports/port"):
                    state = port_node.find("state")
                    if state is None: continue
                    service = port_node.find("service")
                    
                    script_output = []
                    for script in port_node.findall("script"):
                        script_id = script.get("id", "unknown")
                        output = script.get("output", "")
                        script_output.append({"id": script_id, "output": output})
                        has_scripts = True
                    
                    if service is not None and (service.get("version") or service.get("product")):
                        has_version = True
                    
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

    def _finalize_reports(self, records, host, ports, host_info, features):
        try:
            folder = Path(__file__).with_name("reports")
            folder.mkdir(exist_ok=True)
            stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            base = folder / f"nighthawk_{stamp}_{uuid.uuid4().hex[:8]}"
            
            data = {"target": host, "ports": ports, "info": host_info, "created": datetime.datetime.now().isoformat(), "results": records}
            base.with_suffix(".json").write_text(json.dumps(data, indent=2), encoding="utf-8")
            
            csv_fields = ["host", "protocol", "port", "state", "reason", "service"]
            if features["version"]:
                csv_fields.extend(["version", "product", "extrainfo"])
                
            with base.with_suffix(".csv").open("w", newline="", encoding="utf-8") as file:
                writer = csv.DictWriter(file, fieldnames=csv_fields, extrasaction='ignore')
                writer.writeheader()
                writer.writerows({k: self.safe_csv_value(v) for k, v in row.items() if k in csv_fields} for row in records)
                
            txt_content = "\n".join(f"{r['host']}:{r['port']}/{r['protocol']} {r['state']} {r['reason']} {r['service']} {r['version']}" for r in records)
            base.with_suffix(".txt").write_text(txt_content, encoding="utf-8")
            
            rows = ""
            for r in records:
                version_str = f"{r['product']} {r['version']} {r['extrainfo']}".strip() if features["version"] else ""
                
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

            thead = "<tr><th>Host</th><th>Protocol</th><th>Port</th><th>State</th><th>Reason</th><th>Service</th>"
            if features["version"]:
                thead += "<th>Version</th>"
            if features["scripts"]:
                thead += "<th>NSE Output</th>"
            thead += "</tr>"

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
            base.with_suffix(".html").write_text(page, encoding="utf-8")
            self.last_report = base.with_suffix(".html")
            
            if self.current_xml_path is not None:
                self.current_xml_path.unlink(missing_ok=True)
                
            self.update_ui(self.log, f"[+] Reports saved: {base}.html / .json / .csv / .txt")
            self.update_ui(self.finish_scan, "COMPLETE")
            
            if self.auto_open_var.get():
                webbrowser.open(self.last_report.as_uri())
            
        except (OSError, ValueError) as error:
            self.update_ui(self.log, f"[ERROR] Could not create report: {error}")
            self.update_ui(self.finish_scan, "REPORT ERROR")

    def show_history(self):
        folder = Path(__file__).with_name("reports")
        if not folder.exists():
            messagebox.showinfo("History", "No scans have been run yet.")
            return
            
        files = sorted(folder.glob("*.json"), reverse=True)
        if not files:
            messagebox.showinfo("History", "No scans found in the reports folder.")
            return

        win = tk.Toplevel(self.root)
        win.title("Scan History & Diff Engine")
        win.geometry("850x550")
        win.configure(bg=self.BG)
        
        left_frame = tk.Frame(win, bg=self.BG)
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        right_frame = tk.Frame(win, bg=self.BG)
        right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=10, pady=10)

        tk.Label(left_frame, text="SELECT 2 SCANS TO COMPARE", bg=self.BG, fg=self.ACCENT, font=("Consolas", 9, "bold")).pack(anchor="w")
        self.listbox = tk.Listbox(left_frame, bg="#05090c", fg=self.FG, font=("Consolas", 10), relief=tk.FLAT, selectbackground="#19364a", exportselection=False)
        self.listbox.pack(fill=tk.BOTH, expand=True, pady=5)
        
        for f in files:
            try:
                data = json.loads(f.read_text(encoding="utf-8"))
                date = data.get("created", "")[:16].replace("T", " ")
                self.listbox.insert(tk.END, f"{date} | {data.get('target')} | {data.get('ports')}")
            except:
                self.listbox.insert(tk.END, f.name)

        def open_selected(event):
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
            selections = self.listbox.curselection()
            if len(selections) != 2:
                messagebox.showwarning("Compare", "Please select exactly 2 scans (hold Ctrl to select multiple).")
                return
            
            file1 = files[selections[0]]
            file2 = files[selections[1]]
            
            try:
                data1 = json.loads(file1.read_text(encoding="utf-8"))
                data2 = json.loads(file2.read_text(encoding="utf-8"))
                
                ports1 = {r["port"]: r for r in data1.get("results", []) if r["state"] == "open"}
                ports2 = {r["port"]: r for r in data2.get("results", []) if r["state"] == "open"}
                
                self.diff_text.config(state=tk.NORMAL)
                self.diff_text.delete(1.0, tk.END)
                self.diff_text.insert(tk.END, f"Comparing:\nOld: {file1.name}\nNew: {file2.name}\n\n")
                
                new_ports = set(ports2.keys()) - set(ports1.keys())
                if new_ports:
                    self.diff_text.insert(tk.END, "[!] NEWLY OPENED PORTS:\n", ("error",))
                    for p in new_ports:
                        self.diff_text.insert(tk.END, f"  + Port {p} ({ports2[p]['service']})\n", ("open",))
                
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

    @staticmethod
    def safe_csv_value(value):
        text = str(value)
        if text.startswith(("=", "+", "-", "@")):
            return "'" + text
        return text

    def display_command(self, command):
        display_cmd = ["NIGHTHAWK", *command[1:]]
        return subprocess.list2cmdline(display_cmd)

    def clear_output(self):
        self.output.config(state=tk.NORMAL)
        self.output.delete("1.0", tk.END)
        self.output.config(state=tk.DISABLED)

    def stop_scan(self):
        self.is_scanning = False
        if self.scan_process is not None and self.scan_process.poll() is None:
            self.scan_process.terminate()
        self.log("[!] ASSESSMENT ABORTED")
        self.finish_scan("ABORTED")

    def finish_scan(self, status):
        self.is_scanning = False
        self.progress.stop()
        self.progress["value"] = 0
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.open_report_btn.config(state=tk.NORMAL if self.last_report else tk.DISABLED)
        self.status_label.config(text=status, fg=self.ACCENT if status == "COMPLETE" else self.MUTED)

    def open_report(self):
        if self.last_report:
            webbrowser.open(self.last_report.as_uri())

    def export_report(self, extension):
        if self.last_report:
            path = self.last_report.with_suffix("." + extension)
            if path.exists():
                webbrowser.open(path.as_uri())


if __name__ == "__main__":
    root = tk.Tk()
    NighthawkApp(root)
    root.mainloop()