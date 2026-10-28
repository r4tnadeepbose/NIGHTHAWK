import os
import shlex
import shutil
import subprocess
import threading
import tkinter as tk
from tkinter import messagebox, scrolledtext
from tkinter import ttk


class NighthawkApp:
    BG = "#0b1117"
    PANEL = "#111c26"
    FG = "#b8f7d4"
    MUTED = "#6f9d87"
    ACCENT = "#20e08a"
    WARN = "#ffcc66"
    ERROR = "#ff6b6b"

    SCAN_TYPES = {
        "TCP Connect": "-sT",
        "TCP SYN": "-sS",
        "UDP": "-sU",
        "FIN": "-sF",
        "Xmas": "-sX",
        "NULL": "-sN",
        "ACK": "-sA",
    }

    def __init__(self, root):
        self.root = root
        self.root.title("NIGHTHAWK // Advanced Network Scanner")
        self.root.geometry("900x650")
        self.root.minsize(760, 540)
        self.root.configure(bg=self.BG)
        self.is_scanning = False
        self.scan_process = None
        self.create_widgets()

    def create_widgets(self):
        header = tk.Frame(self.root, bg=self.BG, padx=18, pady=14)
        header.pack(fill=tk.X)
        tk.Label(
            header, text="NIGHTHAWK", font=("Consolas", 24, "bold"),
            fg=self.ACCENT, bg=self.BG,
        ).pack(side=tk.LEFT)
        tk.Label(
            header, text="  //  ADVANCED NETWORK RECON", font=("Consolas", 10),
            fg=self.MUTED, bg=self.BG,
        ).pack(side=tk.LEFT, pady=(8, 0))

        panel = tk.Frame(self.root, bg=self.PANEL, padx=14, pady=12)
        panel.pack(fill=tk.X, padx=14)

        self.add_label(panel, "TARGET").grid(row=0, column=0, sticky="w")
        self.host_entry = self.add_entry(panel, "scanme.nmap.org", 34)
        self.host_entry.grid(row=1, column=0, padx=(0, 10), sticky="ew")

        self.add_label(panel, "PORT RANGE").grid(row=0, column=1, sticky="w")
        range_frame = tk.Frame(panel, bg=self.PANEL)
        range_frame.grid(row=1, column=1, padx=(0, 10))
        self.start_port_entry = self.add_entry(range_frame, "1", 7)
        self.start_port_entry.pack(side=tk.LEFT)
        tk.Label(range_frame, text=" - ", fg=self.MUTED, bg=self.PANEL).pack(side=tk.LEFT)
        self.end_port_entry = self.add_entry(range_frame, "1024", 7)
        self.end_port_entry.pack(side=tk.LEFT)

        self.add_label(panel, "SCAN TYPE").grid(row=0, column=2, sticky="w")
        self.scan_type = tk.StringVar(value="TCP Connect")
        scan_menu = tk.OptionMenu(panel, self.scan_type, *self.SCAN_TYPES)
        scan_menu.config(
            bg="#192936", fg=self.FG, activebackground="#223d4c",
            activeforeground=self.ACCENT, highlightthickness=0, width=13,
        )
        scan_menu["menu"].config(bg="#192936", fg=self.FG)
        scan_menu.grid(row=1, column=2, padx=(0, 10), sticky="ew")

        panel.grid_columnconfigure(0, weight=3)
        panel.grid_columnconfigure(1, weight=2)
        panel.grid_columnconfigure(2, weight=2)

        options = tk.Frame(self.root, bg=self.BG, padx=14, pady=10)
        options.pack(fill=tk.X)
        self.service_var = tk.BooleanVar(value=True)
        self.service_check = tk.Checkbutton(
            options, text="SERVICE / VERSION DETECTION", variable=self.service_var,
            fg=self.FG, bg=self.BG, selectcolor=self.PANEL, activebackground=self.BG,
            activeforeground=self.ACCENT,
        )
        self.service_check.pack(side=tk.LEFT)
        self.os_var = tk.BooleanVar(value=False)
        tk.Checkbutton(
            options, text="OS DETECTION", variable=self.os_var,
            fg=self.FG, bg=self.BG, selectcolor=self.PANEL, activebackground=self.BG,
            activeforeground=self.ACCENT,
        ).pack(side=tk.LEFT, padx=16)
        tk.Label(options, text="EXTRA OPTIONS", fg=self.MUTED, bg=self.BG).pack(side=tk.LEFT)
        self.extra_entry = self.add_entry(options, "", 28)
        self.extra_entry.pack(side=tk.LEFT, padx=6, fill=tk.X, expand=True)

        command_frame = tk.Frame(self.root, bg=self.BG, padx=14)
        command_frame.pack(fill=tk.X)
        tk.Label(
            command_frame, text="COMMAND RUN", fg=self.MUTED, bg=self.BG,
            font=("Consolas", 8, "bold"),
        ).pack(side=tk.LEFT)
        self.command_var = tk.StringVar(value="Waiting for scan configuration...")
        self.command_entry = tk.Entry(
            command_frame, textvariable=self.command_var, state="readonly",
            readonlybackground="#070b0f", fg=self.ACCENT, relief=tk.FLAT,
            font=("Consolas", 9),
        )
        self.command_entry.pack(side=tk.LEFT, padx=(10, 0), fill=tk.X, expand=True)

        buttons = tk.Frame(self.root, bg=self.BG, padx=14)
        buttons.pack(fill=tk.X)
        self.start_btn = tk.Button(
            buttons, text="▶  LAUNCH SCAN", command=self.start_scan,
            bg="#123b2b", fg=self.ACCENT, activebackground="#1b6848",
            activeforeground="white", font=("Consolas", 10, "bold"),
            relief=tk.FLAT, padx=14, pady=7,
        )
        self.start_btn.pack(side=tk.LEFT)
        self.stop_btn = tk.Button(
            buttons, text="■  ABORT", command=self.stop_scan, state=tk.DISABLED,
            bg="#3b1b20", fg=self.ERROR, activebackground="#6b2730",
            activeforeground="white", font=("Consolas", 10, "bold"),
            relief=tk.FLAT, padx=14, pady=7,
        )
        self.stop_btn.pack(side=tk.LEFT, padx=8)
        style = ttk.Style()
        style.theme_use("clam")
        style.configure(
            "Nighthawk.Horizontal.TProgressbar",
            troughcolor="#070b0f",
            background=self.ACCENT,
            bordercolor=self.BG,
            lightcolor=self.ACCENT,
            darkcolor=self.ACCENT,
        )
        self.progress = ttk.Progressbar(
            buttons, mode="indeterminate", length=180,
            style="Nighthawk.Horizontal.TProgressbar",
        )
        self.progress.pack(side=tk.LEFT, padx=10)
        self.status_label = tk.Label(
            buttons, text="READY // authorized targets only", fg=self.MUTED, bg=self.BG,
            font=("Consolas", 10),
        )
        self.status_label.pack(side=tk.RIGHT)

        self.output = scrolledtext.ScrolledText(
            self.root, state=tk.DISABLED, bg="#070b0f", fg=self.FG,
            insertbackground=self.ACCENT, font=("Consolas", 10),
            relief=tk.FLAT, padx=10, pady=10,
        )
        self.output.pack(fill=tk.BOTH, expand=True, padx=14, pady=(10, 14))

    def add_label(self, parent, text):
        return tk.Label(parent, text=text, fg=self.MUTED, bg=self.PANEL, font=("Consolas", 8, "bold"))

    def add_entry(self, parent, value, width):
        entry = tk.Entry(
            parent, width=width, bg="#192936", fg=self.FG, insertbackground=self.ACCENT,
            relief=tk.FLAT, font=("Consolas", 10),
        )
        entry.insert(0, value)
        return entry

    def log(self, text):
        self.output.config(state=tk.NORMAL)
        self.output.insert(tk.END, text + "\n")
        self.output.see(tk.END)
        self.output.config(state=tk.DISABLED)

    def update_ui(self, callback, *args):
        self.root.after(0, callback, *args)

    def start_scan(self):
        host = self.host_entry.get().strip()
        nmap = shutil.which("nmap")
        if not host:
            messagebox.showerror("NIGHTHAWK", "Enter a target host or IP address.")
            return
        if nmap is None:
            messagebox.showerror("NIGHTHAWK", "Nmap was not found. Install Nmap and add it to PATH.")
            return
        try:
            start = int(self.start_port_entry.get())
            end = int(self.end_port_entry.get())
        except ValueError:
            messagebox.showerror("NIGHTHAWK", "Ports must be whole numbers.")
            return
        if not 1 <= start <= end <= 65535:
            messagebox.showerror("NIGHTHAWK", "Use a port range from 1 to 65535.")
            return
        try:
            extra = shlex.split(self.extra_entry.get(), posix=False)
        except ValueError as error:
            messagebox.showerror("NIGHTHAWK", f"Invalid extra options: {error}")
            return

        command = [nmap, self.SCAN_TYPES[self.scan_type.get()], "-T5", "-p", f"{start}-{end}"]
        if self.service_var.get():
            command.append("-sV")
        if self.os_var.get():
            command.append("-O")
        command.extend(extra)
        command.append(host)
        command_text = subprocess.list2cmdline(command)

        self.output.config(state=tk.NORMAL)
        self.output.delete("1.0", tk.END)
        self.output.config(state=tk.DISABLED)
        self.command_var.set(command_text)
        self.is_scanning = True
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.progress.start(10)
        self.status_label.config(text="SCANNING // T5 AGGRESSIVE", fg=self.ACCENT)
        threading.Thread(target=self.run_scan, args=(command,), daemon=True).start()

    def run_scan(self, command):
        command_text = subprocess.list2cmdline(command)
        self.update_ui(self.command_var.set, command_text)
        self.update_ui(self.log, "$ " + command_text)
        self.update_ui(self.log, "")
        try:
            flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
            self.scan_process = subprocess.Popen(
                command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, encoding="utf-8", errors="replace", creationflags=flags,
            )
            for line in self.scan_process.stdout:
                if self.is_scanning:
                    self.update_ui(self.log, line.rstrip())
            code = self.scan_process.wait()
        except OSError as error:
            self.update_ui(self.log, f"[ERROR] Could not start Nmap: {error}")
            code = 1
        self.scan_process = None
        if self.is_scanning:
            self.update_ui(self.finish_scan, "COMPLETE" if code == 0 else f"EXIT CODE {code}")

    def stop_scan(self):
        self.is_scanning = False
        if self.scan_process is not None and self.scan_process.poll() is None:
            self.scan_process.terminate()
        self.log("[!] SCAN ABORTED BY OPERATOR")
        self.finish_scan("ABORTED")

    def finish_scan(self, status):
        self.is_scanning = False
        self.progress.stop()
        self.progress["value"] = 0
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.status_label.config(text=status, fg=self.WARN if status == "COMPLETE" else self.MUTED)


if __name__ == "__main__":
    root = tk.Tk()
    NighthawkApp(root)
    root.mainloop()
