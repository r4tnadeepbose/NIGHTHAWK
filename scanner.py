import csv
import datetime
import html
import json
import os
import shlex
import shutil
import subprocess
import tempfile
import threading
import tkinter as tk
import webbrowser
import xml.etree.ElementTree as ET
from pathlib import Path
from tkinter import messagebox, scrolledtext, ttk


class NighthawkApp:
    BG = "#091017"
    PANEL = "#111e29"
    FG = "#b8f7d4"
    MUTED = "#7da18f"
    ACCENT = "#20e08a"
    WARN = "#ffcc66"
    ERROR = "#ff6b6b"

    SCAN_TYPES = {
        "TCP Connect": ("-sT", "Completes a TCP connection; works without administrator privileges."),
        "TCP SYN": ("-sS", "Half-open TCP scan; usually requires administrator/root privileges."),
        "UDP": ("-sU", "Probes UDP services; slower and often requires administrator/root privileges."),
        "FIN": ("-sF", "Sends FIN packets to identify filtered and closed TCP ports."),
        "Xmas": ("-sX", "Sends FIN, PSH, and URG flags for TCP firewall testing."),
        "NULL": ("-sN", "Sends TCP packets without flags for firewall behavior testing."),
        "ACK": ("-sA", "Maps firewall rules; does not identify open ports directly."),
        "Window": ("-sW", "TCP window scan for response behavior on some systems."),
        "Maimon": ("-sM", "TCP Maimon scan using FIN and ACK flags."),
        "Ping Discovery": ("-sn", "Discovers whether a host is online without port scanning."),
        "IP Protocol": ("-sO", "Scans supported IP protocols instead of TCP/UDP ports."),
        "Custom": (None, "Use your own scanner flags. The standard scan controls are hidden."),
    }

    def __init__(self, root):
        self.root = root
        self.root.title("NIGHTHAWK // Advanced Network Scanner")
        self.root.geometry("900x650")
        self.root.minsize(760, 540)
        self.root.configure(bg=self.BG)
        self.is_scanning = False
        self.scan_process = None
        self.last_report = None
        self.current_xml_path = None
        self.build_ui()

    def build_ui(self):
        header = tk.Frame(self.root, bg=self.BG, padx=18, pady=14)
        header.pack(fill=tk.X)
        tk.Label(header, text="NIGHTHAWK", font=("Consolas", 24, "bold"),
                 fg=self.ACCENT, bg=self.BG).pack(side=tk.LEFT)
        tk.Label(header, text="  //  ADVANCED NETWORK RECON",
                 font=("Consolas", 10), fg=self.MUTED, bg=self.BG).pack(side=tk.LEFT, pady=(9, 0))
        tk.Button(
            header, text="?", command=self.show_help, width=3, height=1,
            bg="#19364a", fg=self.ACCENT, activebackground="#28536a",
            activeforeground="white", font=("Consolas", 12, "bold"),
            relief=tk.FLAT, cursor="question_arrow",
        ).pack(side=tk.RIGHT)

        panel = tk.Frame(self.root, bg=self.PANEL, padx=14, pady=12)
        panel.pack(fill=tk.X, padx=14)
        self.labeled_entry(panel, "TARGET", "127.0.0.1",
                           "Hostname or IP address to assess. Scan only systems you own or are authorized to test.", 0, 0, 3)
        self.labeled_entry(panel, "PORTS", "1-1024",
                           "Enter one port (443), a range (1-1024), or a comma-separated list (22,80,443).", 0, 1, 2)
        self.port_entry = self.entries["PORTS"]

        self.add_label(panel, "SCAN TYPE", "Choose the assessment technique. Hover the question mark for details.").grid(row=0, column=2, sticky="w")
        self.scan_type = tk.StringVar(value="TCP Connect")
        self.scan_menu = tk.OptionMenu(panel, self.scan_type, *self.SCAN_TYPES, command=self.scan_type_changed)
        self.style_menu(self.scan_menu)
        self.scan_menu.grid(row=1, column=2, padx=(0, 12), sticky="ew")
        panel.grid_columnconfigure(0, weight=3)
        panel.grid_columnconfigure(1, weight=2)
        panel.grid_columnconfigure(2, weight=2)

        self.options_frame = tk.Frame(self.root, bg=self.BG, padx=16, pady=10)
        self.options_frame.pack(fill=tk.X)
        self.service_var = tk.BooleanVar(value=True)
        self.service_check = self.option(self.options_frame, "SERVICE / VERSION", self.service_var,
                                         "Attempts to identify listening services and versions.")
        self.service_check.pack(side=tk.LEFT)
        self.os_var = tk.BooleanVar(value=False)
        self.os_check = self.option(self.options_frame, "OS DETECTION", self.os_var,
                                    "Attempts operating-system detection; may require elevated privileges.")
        self.os_check.pack(side=tk.LEFT, padx=14)
        self.extra_label = self.add_label(self.options_frame, "EXTRA FLAGS",
                                          "Optional additional flags, such as --reason or --script vuln.")
        self.extra_label.pack(side=tk.LEFT)
        self.extra_entry = self.add_entry(self.options_frame, "--reason", 30)
        self.extra_entry.pack(side=tk.LEFT, padx=6, fill=tk.X, expand=True)
        self.custom_frame = tk.Frame(self.root, bg="#172b28", padx=16, pady=10)
        self.custom_label = self.add_label(self.custom_frame, "CUSTOM COMMAND",
                                           "Enter scanner flags only, for example: -sT -sV --reason. Target and report output are added automatically.")
        self.custom_label.pack(side=tk.LEFT)
        self.custom_entry = self.add_entry(self.custom_frame, "-sT -sV --reason", 55)
        self.custom_entry.pack(side=tk.LEFT, padx=8, fill=tk.X, expand=True)
        self.custom_frame.pack_forget()
        self.entries = {"TARGET": self.target_entry}

        command = tk.Frame(self.root, bg=self.BG, padx=16)
        command.pack(fill=tk.X)
        self.add_label(command, "COMMAND RUN", "The exact command assembled for this scan.").pack(side=tk.LEFT)
        self.command_var = tk.StringVar(value="Waiting for scan configuration...")
        tk.Entry(command, textvariable=self.command_var, state="readonly",
                 readonlybackground="#05090c", fg=self.ACCENT, relief=tk.FLAT,
                 font=("Consolas", 9)).pack(side=tk.LEFT, padx=10, fill=tk.X, expand=True)

        controls = tk.Frame(self.root, bg=self.BG, padx=14, pady=10)
        controls.pack(fill=tk.X)
        start_group = tk.Frame(controls, bg=self.BG)
        start_group.pack(side=tk.LEFT)
        self.start_btn = self.button(start_group, "▶  LAUNCH ASSESSMENT", self.start_scan, "#123b2b", self.ACCENT)
        self.start_btn.pack(side=tk.LEFT)
        abort_group = tk.Frame(controls, bg=self.BG)
        abort_group.pack(side=tk.LEFT, padx=8)
        self.stop_btn = self.button(abort_group, "■  ABORT", self.stop_scan, "#3b1b20", self.ERROR)
        self.stop_btn.config(state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT)
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Nighthawk.Horizontal.TProgressbar", troughcolor="#05090c",
                        background=self.ACCENT, bordercolor=self.BG, lightcolor=self.ACCENT, darkcolor=self.ACCENT)
        self.progress = ttk.Progressbar(controls, mode="indeterminate", length=180,
                                        style="Nighthawk.Horizontal.TProgressbar")
        self.progress.pack(side=tk.LEFT, padx=10)
        self.status_label = tk.Label(controls, text="READY // authorized targets only",
                                     fg=self.MUTED, bg=self.BG, font=("Consolas", 10))
        self.status_label.pack(side=tk.RIGHT)

        self.output = scrolledtext.ScrolledText(self.root, state=tk.DISABLED, bg="#05090c",
                                                fg=self.FG, insertbackground=self.ACCENT,
                                                font=("Consolas", 10), relief=tk.FLAT, padx=10, pady=10)
        self.output.pack(fill=tk.BOTH, expand=True, padx=16, pady=(4, 10))
        reports = tk.Frame(self.root, bg=self.BG, padx=16, pady=4)
        reports.pack(fill=tk.X)
        self.open_report_btn = self.button(reports, "OPEN HTML REPORT", self.open_report, "#19364a", self.ACCENT)
        self.open_report_btn.config(state=tk.DISABLED)
        self.open_report_btn.pack(side=tk.LEFT)
        for label, ext in (("EXPORT JSON", "json"), ("EXPORT CSV", "csv"), ("EXPORT TXT", "txt")):
            button = self.button(reports, label, lambda e=ext: self.export_report(e), "#19364a", self.FG)
            button.pack(side=tk.LEFT, padx=6)

    def labeled_entry(self, parent, label, value, tip, row, column, weight):
        self.add_label(parent, label, tip).grid(row=row, column=column, sticky="w")
        entry = self.add_entry(parent, value, 30)
        entry.grid(row=row + 1, column=column, padx=(0, 12), sticky="ew")
        if not hasattr(self, "entries"):
            self.entries = {}
        self.entries[label] = entry
        if label == "TARGET":
            self.target_entry = entry

    def add_label(self, parent, text, tip):
        frame = tk.Frame(parent, bg=parent.cget("bg"))
        tk.Label(frame, text=text, fg=self.MUTED, bg=parent.cget("bg"),
                 font=("Consolas", 8, "bold")).pack(side=tk.LEFT)
        return frame

    def add_entry(self, parent, value, width):
        entry = tk.Entry(parent, width=width, bg="#192936", fg=self.FG,
                         insertbackground=self.ACCENT, relief=tk.FLAT, font=("Consolas", 10))
        entry.insert(0, value)
        return entry

    def option(self, parent, text, variable, tip):
        check = tk.Checkbutton(parent, text=text, variable=variable, fg=self.FG, bg=self.BG,
                               selectcolor=self.PANEL, activebackground=self.BG, activeforeground=self.ACCENT)
        return check

    def show_help(self):
        messagebox.showinfo(
            "NIGHTHAWK // Help",
            "TARGET\n"
            "Hostname or IP address. Scan only authorized systems.\n\n"
            "PORTS\n"
            "Use one port (443), a range (1-1024), or a list (22,80,443).\n\n"
            "SCAN TYPE\n"
            "Choose TCP, UDP, firewall, discovery, protocol, or Custom mode.\n"
            "Custom mode hides standard options and accepts your own flags.\n\n"
            "SERVICE / VERSION\n"
            "Attempts to identify services and versions.\n\n"
            "OS DETECTION\n"
            "Attempts operating-system detection and may need administrator/root access.\n\n"
            "REPORTS\n"
            "Completed scans create HTML, JSON, CSV, and TXT files in the reports folder.\n"
            "The HTML report opens automatically and includes a searchable results table.\n\n"
            "LAUNCH / ABORT\n"
            "Launch starts the assessment. Abort stops the active process.\n\n"
            "COMMAND RUN\n"
            "Shows the command assembled for the selected settings.",
        )

    def style_menu(self, menu):
        menu.config(bg="#192936", fg=self.FG, activebackground="#223d4c",
                    activeforeground=self.ACCENT, highlightthickness=0, width=14)
        menu["menu"].config(bg="#192936", fg=self.FG)

    def button(self, parent, text, command, background, foreground):
        return tk.Button(parent, text=text, command=command, bg=background, fg=foreground,
                         activebackground="#28536a", activeforeground="white",
                         font=("Consolas", 9, "bold"), relief=tk.FLAT,
                         width=20 if "LAUNCH" in text else 9, padx=12, pady=7)

    def log(self, text):
        self.output.config(state=tk.NORMAL)
        self.output.insert(tk.END, text + "\n")
        self.output.see(tk.END)
        self.output.config(state=tk.DISABLED)

    def update_ui(self, callback, *args):
        self.root.after(0, callback, *args)

    def scan_type_changed(self, selected):
        custom = selected == "Custom"
        if custom:
            self.options_frame.pack_forget()
            self.custom_frame.pack(fill=tk.X, before=self.output)
        else:
            self.custom_frame.pack_forget()
            self.options_frame.pack(fill=tk.X, before=self.output)

    def start_scan(self):
        host = self.target_entry.get().strip()
        ports = self.port_entry.get().strip()
        engine = shutil.which("nmap")
        if not host or not ports:
            messagebox.showerror("NIGHTHAWK", "Target and port expression are required.")
            return
        if engine is None:
            messagebox.showerror("NIGHTHAWK", "The scanner engine was not found. Install it and add it to PATH.")
            return
        if not self.valid_ports(ports):
            messagebox.showerror("NIGHTHAWK", "Use ports like 443, 1-1024, or 22,80,443.")
            return
        try:
            flags = shlex.split(self.custom_entry.get() if self.scan_type.get() == "Custom" else self.extra_entry.get(), posix=False)
        except ValueError as error:
            messagebox.showerror("NIGHTHAWK", f"Invalid custom flags: {error}")
            return
        if self.scan_type.get() == "Custom" and not flags:
            messagebox.showerror("NIGHTHAWK", "Enter custom scanner flags.")
            return
        command = [engine]
        if self.scan_type.get() == "Custom":
            command.extend(flags)
        else:
            command.extend((self.SCAN_TYPES[self.scan_type.get()][0], "-T5"))
            if self.service_var.get() and self.scan_type.get() not in ("Ping Discovery", "IP Protocol"):
                command.append("-sV")
            if self.os_var.get() and self.scan_type.get() not in ("Ping Discovery", "IP Protocol"):
                command.append("-O")
            command.extend(flags)
        self.current_xml_path = Path(self.xml_path())
        command.extend(["-p", ports, "-oX", str(self.current_xml_path), host])
        self.command_var.set(self.display_command(command))
        self.clear_output()
        self.is_scanning = True
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.progress.start(10)
        self.status_label.config(text="RUNNING // REPORT CAPTURE ACTIVE", fg=self.ACCENT)
        threading.Thread(target=self.run_scan, args=(command, host, ports), daemon=True).start()

    @staticmethod
    def valid_ports(expression):
        try:
            for part in expression.split(","):
                if "-" in part:
                    start, end = (int(value) for value in part.split("-", 1))
                    if not 1 <= start <= end <= 65535:
                        return False
                elif not 1 <= int(part) <= 65535:
                    return False
            return bool(expression)
        except ValueError:
            return False

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
                if self.is_scanning:
                    self.update_ui(self.log, line.rstrip())
            code = self.scan_process.wait()
        except OSError as error:
            self.update_ui(self.log, f"[ERROR] Could not start scanner: {error}")
            code = 1
        self.scan_process = None
        if self.is_scanning and code == 0:
            self.update_ui(self.create_reports, host, ports)
        elif self.is_scanning:
            self.update_ui(self.finish_scan, f"EXIT CODE {code}")

    def create_reports(self, host, ports):
        try:
            if self.current_xml_path is None:
                raise OSError("No report data path was created")
            xml_file = self.current_xml_path
            root = ET.parse(xml_file).getroot()
            records = []
            for host_node in root.findall("host"):
                address = host_node.find("address")
                address_text = address.get("addr", host) if address is not None else host
                for port_node in host_node.findall("./ports/port"):
                    state = port_node.find("state")
                    if state is None:
                        continue
                    service = port_node.find("service")
                    records.append({
                        "host": address_text, "protocol": port_node.get("protocol", ""),
                        "port": int(port_node.get("portid", 0)),
                        "state": state.get("state", ""), "reason": state.get("reason", ""),
                        "service": service.get("name", "") if service is not None else "",
                        "version": service.get("version", "") if service is not None else "",
                    })
            folder = Path(__file__).with_name("reports")
            folder.mkdir(exist_ok=True)
            stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            base = folder / f"nighthawk_{stamp}"
            self.last_report = self.write_reports(base, host, ports, records)
            xml_file.unlink(missing_ok=True)
            self.update_ui(self.log, f"[+] Reports saved: {base}.html / .json / .csv / .txt")
            self.update_ui(self.finish_scan, "COMPLETE")
            webbrowser.open(self.last_report.as_uri())
        except (OSError, ET.ParseError, ValueError) as error:
            self.update_ui(self.log, f"[ERROR] Could not create report: {error}")
            self.update_ui(self.finish_scan, "REPORT ERROR")

    def write_reports(self, base, host, ports, records):
        data = {"target": host, "ports": ports, "created": datetime.datetime.now().isoformat(), "results": records}
        base.with_suffix(".json").write_text(json.dumps(data, indent=2), encoding="utf-8")
        with base.with_suffix(".csv").open("w", newline="", encoding="utf-8") as file:
            writer = csv.DictWriter(file, fieldnames=["host", "protocol", "port", "state", "reason", "service", "version"])
            writer.writeheader()
            writer.writerows(records)
        base.with_suffix(".txt").write_text("\n".join(f"{r['host']}:{r['port']}/{r['protocol']} {r['state']} {r['service']} {r['version']}" for r in records), encoding="utf-8")
        rows = "".join("<tr>" + "".join(f"<td>{html.escape(str(r[key]))}</td>" for key in ("host", "protocol", "port", "state", "service", "version")) + "</tr>" for r in records)
        page = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>NIGHTHAWK Report</title>
<style>
body {{ background:#091017; color:#b8f7d4; font:15px Consolas,monospace; padding:30px }}
h1 {{ color:#20e08a }} input {{ background:#111e29; border:1px solid #28536a;
color:#b8f7d4; padding:10px; width: min(520px, 90%); margin-bottom:18px }}
table {{ border-collapse:collapse; width:100% }} td,th {{ border:1px solid #28536a;
padding:8px; text-align:left }} th {{ color:#20e08a }} tr:nth-child(even) {{ background:#111e29 }}
</style>
</head>
<body>
<h1>NIGHTHAWK // Scan Report</h1>
<p>Target: {html.escape(host)} | Ports: {html.escape(ports)}</p>
<input id="filter" type="search" placeholder="Filter host, port, state, or service...">
<table id="results"><thead><tr><th>Host</th><th>Protocol</th><th>Port</th>
<th>State</th><th>Service</th><th>Version</th></tr></thead><tbody>{rows}</tbody></table>
<script>
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
        return base.with_suffix(".html")

    def display_command(self, command):
        return subprocess.list2cmdline(["nighthawk", *command[1:]])

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
            webbrowser.open(path.as_uri())


if __name__ == "__main__":
    root = tk.Tk()
    NighthawkApp(root)
    root.mainloop()
