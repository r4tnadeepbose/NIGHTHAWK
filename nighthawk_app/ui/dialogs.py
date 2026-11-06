"""Standalone dialogs: history, cheatsheet, settings, about, subnet picker."""

import json
import tkinter as tk
from tkinter import messagebox, scrolledtext, ttk

from .. import __version__, VERSION_LABEL
from ..paths import CONFIG_FILE, PROJECT_ROOT, README_FILE, REPORTS_DIR
from .widgets import CheckRow, Panel

CHEATSHEET = """TARGET SPECIFICATION
  nmap 192.168.1.1               single host
  nmap 192.168.1.0/24            CIDR range
  nmap scanme.nmap.org           hostname
  -iL <file>                     targets from file
  --exclude <host>               skip hosts
  -n                             never resolve DNS names

SCAN TECHNIQUES
  -sT   TCP connect (no admin)      -sS   TCP SYN (admin)
  -sU   UDP scan                    -sA   ACK / firewall mapping
  -sF   FIN scan                    -sX   Xmas scan
  -sn   ping discovery only         -sO   IP protocol scan

DISCOVERY
  -Pn   treat host as up            -PS   TCP SYN ping
  -PA   TCP ACK ping                -PR   ARP ping (local)
  --traceroute                      map the path

SERVICE / OS
  -sV                             service and version probes
  -O                              remote OS detection
  -A                              aggressive: -sV -O -sC --traceroute
  --version-intensity <0-9>       tuning for -sV

PORTS
  -p 22,80,443                    explicit ports
  -p 1-1024                       port range
  --top-ports 1000                Nmap's most common ports
  -F                              fast scan (top 100)
  -p-                             all 65535 ports

NSE SCRIPTS
  -sC                             default safe scripts
  --script vuln                   vulnerability category
  --script http-enum              web path enumeration
  --script ssl-enum-ciphers       TLS cipher audit
  --script-args <args>            pass script arguments

TIMING
  -T0 paranoid   -T1 sneaky   -T2 polite
  -T3 normal     -T4 aggressive       -T5 insane
  --min-rate <n>                  minimum packets per second
  --host-timeout <time>           give up after this long

EVASION
  -f                              fragment packets
  --mtu <n>                       custom fragment size
  -D RND:10                       decoy scan
  --spoof-mac 0                   random MAC address
  -g 53                           source port 53
  --badsum                        invalid checksums

OUTPUT
  -oN / -oX / -oG / -oA           normal / XML / grepable / all
  -v                              verbose
  --reason                        show the reason for each state
  --open                          only show open ports
"""


class DialogMixin:
    """The secondary windows reachable from the header and tabs."""

    def show_cheatsheet(self):
        """Open the searchable Nmap cheatsheet."""
        win = tk.Toplevel(self.root)
        win.title("NIGHTHAWK — Nmap cheatsheet")
        win.geometry("920x720")
        win.minsize(720, 520)
        win.configure(bg=self.BG)

        header = tk.Frame(win, bg=self.BG)
        header.pack(fill=tk.X, padx=18, pady=(16, 8))
        tk.Label(header, text="Nmap cheatsheet", bg=self.BG, fg=self.FG,
                 font=("Consolas", 17, "bold"), anchor="w").pack(fill=tk.X)
        tk.Label(header, text="Search to jump through common flags and examples.",
                 bg=self.BG, fg=self.MUTED, font=("Segoe UI", 9), anchor="w").pack(fill=tk.X, pady=(2, 0))

        search_row = tk.Frame(win, bg=self.BG)
        search_row.pack(fill=tk.X, padx=18, pady=(0, 8))
        query = tk.StringVar()
        entry = self.make_entry(search_row, "")
        entry.configure(textvariable=query)
        entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        text = scrolledtext.ScrolledText(win, bg=self.PANEL2, fg=self.FG, relief=tk.FLAT,
                                         font=("Consolas", 9), padx=14, pady=12,
                                         highlightbackground=self.BORDER, highlightthickness=1)
        text.pack(fill=tk.BOTH, expand=True, padx=18, pady=(0, 10))
        text.insert(tk.END, CHEATSHEET)
        text.config(state=tk.DISABLED)
        text.tag_config("match", background=self.SELECT, foreground=self.ACCENT)

        def find_next(_event=None):
            text.tag_remove("match", "1.0", tk.END)
            needle = query.get().strip()
            if not needle:
                return
            start = "1.0"
            found_any = False
            while True:
                index = text.search(needle, start, nocase=True, stopindex=tk.END)
                if not index:
                    break
                end = f"{index}+{len(needle)}c"
                text.tag_add("match", index, end)
                if not found_any:
                    text.see(index)
                found_any = True
                start = end
            if not found_any:
                self.set_status("NO CHEATSHEET MATCH", self.MUTED)

        entry.bind("<Return>", find_next)
        self.make_button(search_row, "FIND", find_next, "default",
                         font=("Consolas", 8, "bold"), pady=5).pack(side=tk.LEFT, padx=(8, 0))
        self._apply_theme_to(win)

    def show_history(self):
        """Two-panel scan history with an open-port diff."""
        files = sorted(REPORTS_DIR.glob("*.json"), reverse=True) if REPORTS_DIR.exists() else []
        if not files:
            messagebox.showinfo("Scan history", "No completed scan reports are available yet.", parent=self.root)
            return

        win = tk.Toplevel(self.root)
        win.title("NIGHTHAWK — Scan history")
        win.geometry("1160x700")
        win.minsize(940, 540)
        win.configure(bg=self.BG)
        win.grid_rowconfigure(1, weight=1)
        win.grid_columnconfigure(0, weight=1)

        header = tk.Frame(win, bg=self.BG)
        header.grid(row=0, column=0, sticky="ew", padx=18, pady=(16, 10))
        tk.Label(header, text="Scan history", bg=self.BG, fg=self.FG,
                 font=("Consolas", 18, "bold"), anchor="w").pack(fill=tk.X)
        tk.Label(header, text="Select two reports to compare their open ports. Double-click one to open its HTML view.",
                 bg=self.BG, fg=self.MUTED, font=("Segoe UI", 9), anchor="w").pack(fill=tk.X, pady=(2, 0))

        workspace = tk.PanedWindow(win, orient=tk.HORIZONTAL, sashwidth=5, bg=self.BG, bd=0,
                                   sashrelief=tk.FLAT)
        workspace.grid(row=1, column=0, sticky="nsew", padx=18, pady=(0, 12))
        left = tk.Frame(workspace, bg=self.PANEL, highlightbackground=self.BORDER, highlightthickness=1)
        right = tk.Frame(workspace, bg=self.PANEL, highlightbackground=self.BORDER, highlightthickness=1)
        workspace.add(left, minsize=460)
        workspace.add(right, minsize=400)

        tk.Label(left, text="COMPLETED SCANS", bg=self.PANEL, fg=self.MUTED,
                 font=("Consolas", 9, "bold"), anchor="w").pack(fill=tk.X, padx=14, pady=(12, 7))
        columns = ("date", "target", "ports", "open", "findings")
        history = ttk.Treeview(left, columns=columns, show="headings", selectmode="extended",
                               style="Nighthawk.Treeview")
        for key, title, width in (("date", "DATE", 140), ("target", "TARGET", 140),
                                  ("ports", "PORTS", 105), ("open", "OPEN", 55),
                                  ("findings", "FIND", 55)):
            history.heading(key, text=title)
            history.column(key, width=width, anchor="w")
        history.pack(fill=tk.BOTH, expand=True, padx=12, pady=(0, 12))

        report_files = {}
        for report in files:
            try:
                payload = json.loads(report.read_text(encoding="utf-8"))
                created = payload.get("created", "").replace("T", " ")[:16] or report.stem
                open_count = sum(1 for item in payload.get("results", []) if item.get("state") == "open")
                findings = sum(len(item.get("scripts", [])) for item in payload.get("results", []))
                item_id = history.insert("", tk.END, values=(created, payload.get("target", "—"),
                                                             payload.get("ports", "—"), open_count, findings))
            except (OSError, ValueError, json.JSONDecodeError):
                item_id = history.insert("", tk.END, values=(report.stem, "—", "—", "—", "—"))
            report_files[item_id] = report

        tk.Label(right, text="COMPARISON", bg=self.PANEL, fg=self.MUTED,
                 font=("Consolas", 9, "bold"), anchor="w").pack(fill=tk.X, padx=14, pady=(12, 7))
        diff = scrolledtext.ScrolledText(right, state=tk.DISABLED, bg=self.PANEL2, fg=self.FG,
                                         insertbackground=self.ACCENT, relief=tk.FLAT,
                                         font=("Consolas", 10), padx=14, pady=12)
        diff.pack(fill=tk.BOTH, expand=True, padx=12, pady=(0, 12))
        diff.tag_config("added", foreground=self.HEALTHY)
        diff.tag_config("removed", foreground=self.ERROR)
        diff.tag_config("heading", foreground=self.ACCENT, font=("Consolas", 10, "bold"))
        diff.tag_config("muted", foreground=self.MUTED)

        actions = tk.Frame(win, bg=self.BG)
        actions.grid(row=2, column=0, sticky="ew", padx=18, pady=(0, 16))
        note = tk.StringVar(value="Choose two reports to compare their open ports.")
        tk.Label(actions, textvariable=note, bg=self.BG, fg=self.MUTED,
                 font=("Segoe UI", 9)).pack(side=tk.LEFT)

        def selected_reports():
            return [report_files[item] for item in history.selection() if item in report_files]

        def write_diff():
            chosen = selected_reports()
            if len(chosen) != 2:
                note.set("Select exactly two reports to compare.")
                return
            try:
                payloads = sorted((json.loads(path.read_text(encoding="utf-8")) for path in chosen),
                                  key=lambda payload: payload.get("created", ""))
                older, newer = payloads
                old_ports = {(item.get("host"), item.get("protocol"), item.get("port")): item
                             for item in older.get("results", []) if item.get("state") == "open"}
                new_ports = {(item.get("host"), item.get("protocol"), item.get("port")): item
                             for item in newer.get("results", []) if item.get("state") == "open"}
                added = sorted(set(new_ports) - set(old_ports))
                removed = sorted(set(old_ports) - set(new_ports))
                diff.config(state=tk.NORMAL)
                diff.delete("1.0", tk.END)
                diff.insert(tk.END, "REPORT COMPARISON\n", "heading")
                diff.insert(tk.END, f"Older: {older.get('created', '—')[:16].replace('T', ' ')} {older.get('target', '—')}  |  "
                                    f"Newer: {newer.get('created', '—')[:16].replace('T', ' ')} {newer.get('target', '—')}\n\n", "muted")
                if added:
                    diff.insert(tk.END, "NEWLY OPEN PORTS\n", "heading")
                    for host, protocol, port in added:
                        record = new_ports[(host, protocol, port)]
                        diff.insert(tk.END, f"+ {host} {port}/{protocol}  {record.get('service', 'unknown')}\n", "added")
                    diff.insert(tk.END, "\n")
                if removed:
                    diff.insert(tk.END, "NO LONGER OPEN\n", "heading")
                    for host, protocol, port in removed:
                        record = old_ports[(host, protocol, port)]
                        diff.insert(tk.END, f"- {host} {port}/{protocol}  {record.get('service', 'unknown')}\n", "removed")
                if not added and not removed:
                    diff.insert(tk.END, "No open-port changes were found.", "muted")
                diff.config(state=tk.DISABLED)
                note.set(f"Compared {chosen[0].name} with {chosen[1].name}.")
            except (OSError, ValueError, json.JSONDecodeError) as error:
                messagebox.showerror("Comparison failed", str(error), parent=win)

        def open_selected(_event=None):
            chosen = selected_reports()
            if chosen:
                report = chosen[0].with_suffix(".html")
                if report.exists():
                    self.open_path(report)

        history.bind("<Double-1>", open_selected)
        self.make_button(actions, "OPEN REPORT", open_selected, "default",
                         font=("Consolas", 9, "bold"), pady=8).pack(side=tk.RIGHT, padx=(8, 0))
        self.make_button(actions, "COMPARE SELECTED", write_diff, "primary",
                         font=("Consolas", 9, "bold"), pady=8).pack(side=tk.RIGHT)
        self._apply_theme_to(win)

    def show_settings(self):
        """Open a small settings surface for theme, config, and shortcuts."""
        win = tk.Toplevel(self.root)
        win.title("NIGHTHAWK — Settings")
        win.geometry("640x520")
        win.minsize(560, 460)
        win.configure(bg=self.BG)

        header = tk.Frame(win, bg=self.BG)
        header.pack(fill=tk.X, padx=20, pady=(18, 8))
        tk.Label(header, text="Settings", bg=self.BG, fg=self.FG,
                 font=("Consolas", 18, "bold"), anchor="w").pack(fill=tk.X)
        tk.Label(header, text="Preferences are stored locally next to the scanner.",
                 bg=self.BG, fg=self.MUTED, font=("Segoe UI", 9), anchor="w").pack(fill=tk.X, pady=(2, 0))

        panel = Panel(win, self, title="Application")
        panel.pack(fill=tk.X, padx=20, pady=8)
        for label, value in (("Version", f"{__version__} ({VERSION_LABEL})"),
                             ("Theme", "Dark" if self.dark else "Light"),
                             ("Config file", str(CONFIG_FILE)),
                             ("Reports folder", str(REPORTS_DIR))):
            row = tk.Frame(panel.body, bg=self.PANEL)
            row.pack(fill=tk.X, padx=15, pady=6)
            tk.Label(row, text=label, width=14, anchor="w", bg=self.PANEL, fg=self.MUTED,
                     font=("Consolas", 8, "bold")).pack(side=tk.LEFT)
            tk.Label(row, text=value, anchor="w", bg=self.PANEL, fg=self.FG,
                     font=("Consolas", 9)).pack(side=tk.LEFT, fill=tk.X, expand=True)

        shortcuts = Panel(win, self, title="Keyboard shortcuts")
        shortcuts.pack(fill=tk.BOTH, expand=True, padx=20, pady=8)
        cheat = (
            "Ctrl+1…5    switch dashboard tabs\n"
            "Ctrl+R      start a scan\n"
            "Ctrl+.      stop the running scan\n"
            "Ctrl+L      focus the port filter\n"
            "Ctrl+T      toggle the theme\n"
            "Ctrl+H      open scan history\n"
        )
        tk.Label(shortcuts.body, text=cheat, justify=tk.LEFT, anchor="w", bg=self.PANEL,
                 fg=self.MUTED, font=("Consolas", 9)).pack(fill=tk.X, padx=15, pady=12)

        actions = tk.Frame(win, bg=self.BG)
        actions.pack(fill=tk.X, padx=20, pady=(0, 16))
        self.make_button(actions, "TOGGLE THEME", self.toggle_theme, "default").pack(side=tk.LEFT)
        self.make_button(actions, "SAVE PREFERENCES", self.save_and_confirm, "primary").pack(side=tk.LEFT, padx=8)
        self.make_button(actions, "OPEN CONFIG FOLDER", lambda: self.open_path(PROJECT_ROOT), "ghost").pack(side=tk.RIGHT)
        self._apply_theme_to(win)

    def save_and_confirm(self):
        self.save_config()
        self.set_status("PREFERENCES SAVED", self.ACCENT)

    def show_about(self):
        """About window with version, capabilities, and a safety note."""
        win = tk.Toplevel(self.root)
        win.title("NIGHTHAWK — About")
        win.geometry("620x560")
        win.resizable(False, False)
        win.configure(bg=self.BG)

        top = tk.Frame(win, bg=self.BG)
        top.pack(fill=tk.X, padx=22, pady=(22, 10))
        if hasattr(self, "logo_image"):
            tk.Label(top, image=self.logo_image, bg=self.BG).pack(side=tk.LEFT, padx=(0, 16))
        text = tk.Frame(top, bg=self.BG)
        text.pack(side=tk.LEFT)
        tk.Label(text, text="NIGHTHAWK", bg=self.BG, fg=self.ACCENT,
                 font=("Consolas", 24, "bold"), anchor="w").pack(fill=tk.X)
        tk.Label(text, text=f"ADVANCED NETWORK SCANNER · {VERSION_LABEL}", bg=self.BG,
                 fg=self.MUTED, font=("Consolas", 9), anchor="w").pack(fill=tk.X)
        tk.Label(text, text=f"version {__version__}", bg=self.BG, fg=self.MUTED,
                 font=("Consolas", 8), anchor="w").pack(fill=tk.X, pady=(2, 0))

        body = tk.Frame(win, bg=self.BG)
        body.pack(fill=tk.BOTH, expand=True, padx=22)
        features = (
            "• Five dashboard tabs with counts and keyboard shortcuts\n"
            "• Live Nmap output, elapsed timer, and copy controls\n"
            "• Sortable and filterable port table with service details\n"
            "• NSE finding browser with search and copy\n"
            "• Service mix, recommendations, and a shared risk engine\n"
            "• HTML, JSON, CSV, and TXT reports with a theme-aware report\n"
            "• Scan history diff, saved presets, and a searchable cheatsheet"
        )
        tk.Label(body, text=features, justify=tk.LEFT, anchor="w", bg=self.BG, fg=self.MUTED,
                 font=("Segoe UI", 10)).pack(fill=tk.X, pady=(6, 14))
        tk.Label(body, text="SAFETY", bg=self.BG, fg=self.ACCENT,
                 font=("Consolas", 9, "bold"), anchor="w").pack(fill=tk.X)
        tk.Label(body, text="Only scan hosts you own or have explicit permission to test. "
                            "NIGHTHAWK validates targets and blocks destructive output flags, "
                            "but authorization is always your responsibility.",
                 justify=tk.LEFT, anchor="w", wraplength=560, bg=self.BG, fg=self.MUTED,
                 font=("Segoe UI", 9)).pack(fill=tk.X, pady=(4, 16))

        actions = tk.Frame(win, bg=self.BG)
        actions.pack(fill=tk.X, padx=22, pady=(0, 18))
        self.make_button(actions, "OPEN README", lambda: self.open_path(README_FILE), "default").pack(side=tk.LEFT)
        self.make_button(actions, "CLOSE", win.destroy, "primary").pack(side=tk.RIGHT)
        self._apply_theme_to(win)

    def show_subnet_results(self, ips):
        """Pick discovered hosts from a CIDR sweep."""
        self.finish_scan("READY")
        win = tk.Toplevel(self.root)
        win.title("NIGHTHAWK — Live hosts")
        win.geometry("520x620")
        win.configure(bg=self.BG)
        tk.Label(win, text="Live hosts found", bg=self.BG, fg=self.FG,
                 font=("Consolas", 16, "bold"), anchor="w").pack(fill=tk.X, padx=18, pady=(16, 2))
        tk.Label(win, text="Select the hosts you want to scan next.", bg=self.BG, fg=self.MUTED,
                 font=("Segoe UI", 9), anchor="w").pack(fill=tk.X, padx=18, pady=(0, 10))

        panel = Panel(win, self, title=f"{len(ips)} host(s)")
        panel.pack(fill=tk.BOTH, expand=True, padx=18, pady=(0, 10))
        variables = []
        for ip in ips:
            variable = tk.BooleanVar(value=True)
            row = CheckRow(panel.body, self, ip, "Include this host", variable)
            row.pack(fill=tk.X, padx=4, pady=1)
            self.register_themed(row)
            variables.append(variable)

        def scan_selected():
            selected = [ip for ip, variable in zip(ips, variables) if variable.get()]
            if not selected:
                messagebox.showwarning("NIGHTHAWK", "Select at least one host.", parent=win)
                return
            win.destroy()
            self.target_entry.delete(0, tk.END)
            self.target_entry.insert(0, ",".join(selected))
            self.start_scan()

        self.make_button(win, "SCAN SELECTED", scan_selected, "primary", pady=10).pack(
            fill=tk.X, padx=18, pady=(0, 16))
        self._apply_theme_to(win)
