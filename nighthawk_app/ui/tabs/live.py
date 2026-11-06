"""Live output tab: command preview, streaming log, timer, and log tools."""

import datetime
import re
import tkinter as tk
from tkinter import ttk


class LiveMixin:
    """Stream Nmap output into a themed console."""

    def build_live(self, tab):
        top = tk.Frame(tab, bg=self.BG)
        top.pack(fill=tk.X, padx=8, pady=(8, 4))
        tk.Label(top, text="COMMAND", bg=self.BG, fg=self.MUTED,
                 font=("Consolas", 8, "bold")).pack(side=tk.LEFT, padx=(0, 8))
        self.command_var = tk.StringVar(value="Waiting for scan configuration…")
        tk.Label(top, textvariable=self.command_var, bg=self.PANEL2, fg=self.ACCENT,
                 anchor="w", font=("Consolas", 9), padx=10, pady=8).pack(
            side=tk.LEFT, fill=tk.X, expand=True)
        self.make_button(top, "COPY", self.copy_command, "default",
                         font=("Consolas", 8, "bold"), pady=6).pack(side=tk.LEFT, padx=(8, 0))
        self.progress = ttk.Progressbar(top, mode="indeterminate", length=150,
                                           style="Nighthawk.Horizontal.TProgressbar")
        self.progress.pack(side=tk.RIGHT, padx=(10, 0))
        self.progress.pack_forget()

        status = tk.Frame(tab, bg=self.BG)
        status.pack(fill=tk.X, padx=8, pady=(2, 4))
        self.live_info_label = tk.Label(status, text="MAC: ---  |  OS: ---", bg=self.BG,
                                        fg=self.MUTED, font=("Consolas", 9), anchor="w")
        self.live_info_label.pack(side=tk.LEFT)
        self.elapsed_var = tk.StringVar(value="00:00")
        tk.Label(status, textvariable=self.elapsed_var, bg=self.BG, fg=self.MUTED,
                 font=("Consolas", 9, "bold")).pack(side=tk.LEFT, padx=16)
        self._autoscroll = True
        self.autoscroll_btn = self.make_button(status, "AUTO-SCROLL ON", self.toggle_autoscroll,
                                               "ghost", font=("Consolas", 8, "bold"), pady=4)
        self.autoscroll_btn.pack(side=tk.RIGHT)
        self.make_button(status, "COPY LOG", self.copy_log, "ghost",
                         font=("Consolas", 8, "bold"), pady=4).pack(side=tk.RIGHT, padx=6)
        self.make_button(status, "CLEAR", self.clear_output, "ghost",
                         font=("Consolas", 8, "bold"), pady=4).pack(side=tk.RIGHT)

        self.output = tk.Text(tab, state=tk.DISABLED, bg=self.PANEL2, fg=self.FG,
                              insertbackground=self.ACCENT, relief=tk.FLAT, wrap=tk.NONE,
                              font=("Consolas", 10), padx=14, pady=12,
                              highlightbackground=self.BORDER, highlightthickness=1)
        self.output.pack(fill=tk.BOTH, expand=True, padx=8, pady=(0, 8))
        self.output.tag_config("open", foreground=self.HEALTHY)
        self.output.tag_config("closed", foreground=self.WARN)
        self.output.tag_config("error", foreground=self.ERROR)

        self._elapsed_job = None
        self.scan_started_at = None

    def log(self, text):
        """Append one line to the live log and color it by simple keywords."""
        self.output.config(state=tk.NORMAL)
        lowered = text.lower()
        if "open|filtered" in lowered or "closed|filtered" in lowered or "unfiltered" in lowered:
            tag = ("closed",)
        elif "open" in lowered:
            tag = ("open",)
        elif "closed" in lowered or "filtered" in lowered:
            tag = ("closed",)
        elif "error" in lowered or "fail" in lowered:
            tag = ("error",)
        else:
            tag = ()
        self.output.insert(tk.END, text + "\n", tag)
        if self._autoscroll:
            self.output.see(tk.END)
        self.output.config(state=tk.DISABLED)

    def clear_output(self):
        self.output.config(state=tk.NORMAL)
        self.output.delete("1.0", tk.END)
        self.output.config(state=tk.DISABLED)

    def copy_log(self):
        text = self.output.get("1.0", tk.END).strip()
        if not text:
            self.set_status("LOG IS EMPTY", self.MUTED)
            return
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        self.set_status("LOG COPIED", self.ACCENT)

    def copy_command(self):
        command = self.command_var.get()
        if not command:
            return
        self.root.clipboard_clear()
        self.root.clipboard_append(command)
        self.set_status("COMMAND COPIED", self.ACCENT)

    def toggle_autoscroll(self):
        self._autoscroll = not self._autoscroll
        self.autoscroll_btn.configure(text=f"AUTO-SCROLL {'ON' if self._autoscroll else 'OFF'}")
        if self._autoscroll:
            self.output.see(tk.END)

    def update_live_info(self, text):
        """Read MAC and OS hints from a streamed Nmap line."""
        mac_match = re.search(r"MAC Address: ([0-9A-F:]+) \(([^)]+)\)", text)
        if mac_match:
            self.live_host_info["mac"] = f"{mac_match.group(1)} ({mac_match.group(2)})"
        os_match = re.search(r"OS details: (.*)", text)
        if os_match:
            self.live_host_info["os"] = os_match.group(1)
        self.set_live_info(f"MAC: {self.live_host_info['mac']}  |  OS: {self.live_host_info['os']}")

    def set_live_info(self, text):
        self.live_info_label.config(text=text)

    def start_elapsed(self):
        """Tick the elapsed timer while a scan is running."""
        self.stop_elapsed()
        self._tick_elapsed()

    def _tick_elapsed(self):
        if not self.is_scanning:
            return
        started = getattr(self, "scan_started_at", None) or datetime.datetime.now()
        elapsed = max(0, int((datetime.datetime.now() - started).total_seconds()))
        self.elapsed_var.set(f"{elapsed // 60:02d}:{elapsed % 60:02d}")
        self._elapsed_job = self.root.after(500, self._tick_elapsed)

    def stop_elapsed(self):
        if self._elapsed_job is not None:
            try:
                self.root.after_cancel(self._elapsed_job)
            except tk.TclError:
                pass
            self._elapsed_job = None
        if hasattr(self, "elapsed_var"):
            started = getattr(self, "scan_started_at", None)
            if started:
                elapsed = max(0, int((datetime.datetime.now() - started).total_seconds()))
                self.elapsed_var.set(f"{elapsed // 60:02d}:{elapsed % 60:02d}")
