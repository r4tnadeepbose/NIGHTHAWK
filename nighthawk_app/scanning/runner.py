"""Nmap process orchestration: validation, threading, streaming, aborting."""

import datetime
import os
import re
import shutil
import subprocess
import tempfile
import threading
import tkinter as tk
from pathlib import Path
from tkinter import messagebox

from .options import build_command, valid_ports


class ScanMixin:
    """Everything that turns the sidebar into a running Nmap process."""

    def _checked_options(self):
        """Return the current checkbox state as a plain dictionary."""
        return {key: var.get() for key, var in self.check_vars.items()}

    def _flags_text(self):
        if self.scan_type.get() == "Custom Flags":
            return self.custom_entry.get()
        return self.extra_entry.get()

    def start_scan(self):
        """Validate the form, build the command, and start the scan thread."""
        host = self.target_entry.get().strip()
        ports = self.port_entry.get().strip()
        engine = shutil.which("nmap")

        self.config.update({
            "target": host,
            "ports": ports,
            "scan_type": self.scan_type.get(),
            "timing": self.timing_var.get(),
            "extra_flags": self.extra_entry.get(),
            "auto_open": self.auto_open_var.get(),
            **self._checked_options(),
        })
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
        if not valid_ports(ports) and ports != "N/A":
            messagebox.showerror("NIGHTHAWK", "Use ports like 443, 1-1024, 22,80,443, or --top-ports 100.")
            return

        self.current_xml_path = self.xml_path()
        try:
            command = build_command(
                engine,
                scan_type=self.scan_type.get(),
                timing=self.timing_var.get(),
                ports=ports,
                flags_text=self._flags_text(),
                check_state=self._checked_options(),
                custom_flags=self.scan_type.get() == "Custom Flags",
                xml_path=self.current_xml_path,
                target=host,
            )
        except (ValueError, KeyError) as error:
            self.current_xml_path.unlink(missing_ok=True)
            self.current_xml_path = None
            messagebox.showerror("NIGHTHAWK", f"Invalid scan configuration: {error}")
            return

        self._execute_command(command, host, ports)

    def _execute_command(self, command, host, ports):
        """Prepare the interface and launch the worker thread."""
        self.scan_started_at = datetime.datetime.now()
        self.last_command = self.display_command(command)
        self.command_var.set(self.last_command)
        self.clear_output()
        self.is_scanning = True
        self.live_host_info = {"mac": "Scanning...", "os": "Scanning..."}
        self.set_live_info("MAC: ---  |  OS: ---")
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.show_progress()
        self.set_status("RUNNING", self.ACCENT)
        self.start_elapsed()
        self.select_tab("live")
        threading.Thread(target=self.run_scan, args=(command, host, ports), daemon=True).start()

    def run_scan(self, command, host, ports):
        """Stream Nmap output off the UI thread, then build reports on success."""
        self.update_ui(self.log, "$ " + self.display_command(command))
        try:
            flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
            self.scan_process = subprocess.Popen(
                command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, encoding="utf-8", errors="replace", creationflags=flags,
            )
            for line in self.scan_process.stdout:
                if not self.is_scanning:
                    continue
                stripped = line.strip()
                self.update_ui(self.update_live_info, line)
                if stripped.startswith(("Starting Nmap", "Nmap done", "Nmap scan report for")):
                    continue
                self.update_ui(self.log, line.rstrip())
            code = self.scan_process.wait()
        except OSError as error:
            self.update_ui(self.log, f"[ERROR] Could not start scanner: {error}")
            code = 1
        except Exception as error:  # keep the UI usable if the stream thread fails
            self.update_ui(self.log, f"[ERROR] Scan failed: {error}")
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

    def run_subnet_sweep(self, subnet, engine):
        """Discover live hosts on a CIDR range before offering them for scanning."""
        self.clear_output()
        self.is_scanning = True
        self.start_btn.config(state=tk.DISABLED)
        self.set_status("DISCOVERING", self.WARN)
        self.show_progress()
        self.start_elapsed()
        self.select_tab("live")
        self.update_ui(self.log, f"[*] Running ping sweep on {subnet}...")

        def sweep():
            command = [engine, "-sn", "-T4", subnet]
            try:
                flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
                proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                        text=True, creationflags=flags)
                output, _ = proc.communicate()
                ips = re.findall(r"Nmap scan report for (?:[^\s]+\s)?\(?([0-9\.]+)\)?", output)
                if not ips:
                    self.update_ui(self.log, "[-] No live hosts found.")
                    self.update_ui(self.finish_scan, "NO HOSTS")
                    return
                self.update_ui(self.log, f"[+] Found {len(ips)} live hosts.")
                self.update_ui(self.show_subnet_results, ips)
            except (OSError, ValueError) as error:
                self.update_ui(self.log, f"[ERROR] {error}")
                self.update_ui(self.finish_scan, "ERROR")

        threading.Thread(target=sweep, daemon=True).start()

    def show_progress(self):
        self.progress.pack(side=tk.RIGHT, padx=(10, 0))
        self.progress.configure(mode="indeterminate")
        self.progress.start(10)

    def hide_progress(self):
        self.progress.stop()
        self.progress.configure(mode="determinate", value=0)
        self.progress.pack_forget()

    def stop_scan(self):
        """Ask Nmap to stop and restore the idle UI."""
        self.is_scanning = False
        if self.scan_process is not None and self.scan_process.poll() is None:
            self.scan_process.terminate()
        self.log("[!] ASSESSMENT ABORTED")
        self.finish_scan("ABORTED")

    def finish_scan(self, status):
        """Reset controls, progress, and the status pill after any run."""
        self.is_scanning = False
        self.hide_progress()
        self.stop_elapsed()
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.open_report_btn.config(state=tk.NORMAL if self.last_report else tk.DISABLED)
        self.set_status(status, self.ACCENT if status == "COMPLETE" else self.MUTED)
        self.refresh_export()

    def display_command(self, command):
        """Show a readable command preview without exposing the Nmap path."""
        return subprocess.list2cmdline(["NIGHTHAWK", *command[1:]])

    def xml_path(self):
        """Create an empty temporary filename for Nmap's XML output."""
        handle, path = tempfile.mkstemp(suffix=".xml", prefix="nighthawk_")
        os.close(handle)
        return Path(path)

    @staticmethod
    def parse_flags(text):
        from .options import parse_flags
        return parse_flags(text)

    @staticmethod
    def valid_ports(expression):
        return valid_ports(expression)

    def set_status(self, text, color):
        """Update the header status pill with an optional detail."""
        self.status_label.config(text=text, fg=color)
