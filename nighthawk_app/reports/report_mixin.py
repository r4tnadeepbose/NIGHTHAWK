"""Report creation, opening, and export actions."""

import datetime
import os
import uuid
import webbrowser
from pathlib import Path
from tkinter import messagebox

from .exporters import ensure_reports_dir, write_reports
from .html import render_report
from .risk import SEVERITY_ROLES, assess
from .. import __version__
from ..paths import REPORTS_DIR
from ..scanning.options import MAX_REPORT_XML_BYTES, SCAN_TYPES, TIMING_TEMPLATES
from ..scanning.parser import parse_nmap_xml

FLAG_LABELS = {
    "service": "-sV", "os": "-O", "traceroute": "--traceroute",
    "skip_ping": "-Pn", "verbose": "-v", "reasons": "--reason",
}
SCRIPT_LABELS = {
    "nse_default": "-sC", "nse_vuln": "vuln", "nse_http": "http-enum", "nse_ssl": "ssl-enum-ciphers",
}


class ReportMixin:
    """Turn parsed scan data into the four report formats."""

    def create_reports(self, host, ports):
        """Parse the XML Nmap produced and finalize every report format."""
        try:
            if self.current_xml_path is None:
                raise OSError("No report data path was created")
            if self.current_xml_path.stat().st_size > MAX_REPORT_XML_BYTES:
                raise ValueError("Scan XML exceeds the 25 MB report limit")
            parsed = parse_nmap_xml(self.current_xml_path, host)
            self._finalize_reports(
                parsed["records"], host, ports, parsed["info"], parsed["features"], parsed["meta"]
            )
        except Exception as error:
            self._discard_current_xml()
            self.update_ui(self.log, f"[ERROR] Could not parse scan data: {error}")
            self.update_ui(self.finish_scan, "REPORT ERROR")

    def _finalize_reports(self, records, host, ports, host_info, features, meta):
        """Write JSON, CSV, TXT, and the standalone HTML dashboard."""
        try:
            folder = ensure_reports_dir()
            stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            base = folder / f"nighthawk_{stamp}_{uuid.uuid4().hex[:8]}"

            elapsed = meta.get("elapsed") or self.elapsed_seconds()
            data = {
                "target": host,
                "ports": ports,
                "info": host_info,
                "created": datetime.datetime.now().isoformat(),
                "nighthawk_version": __version__,
                "nmap_version": meta.get("nmap_version", "Unknown"),
                "started": meta.get("started", ""),
                "hosts_up": meta.get("hosts_up", 1),
                "hosts_scanned": meta.get("hosts_scanned", meta.get("hosts_up", 1)),
                "ports_total": meta.get("ports_total", len(records)),
                "port_summary": meta.get("port_summary", []),
                "open_ports": sum(1 for record in records if record.get("state") == "open"),
                "script_findings": sum(len(record.get("scripts", [])) for record in records),
                "duration": str(datetime.timedelta(seconds=int(elapsed))),
                "command": self.last_command or self.command_var.get(),
                "options": self.enabled_options(),
                "results": records,
            }
            self.last_scan_data = data
            write_reports(base, data, features)
            base.with_suffix(".html").write_text(
                render_report(data, base, self.PALETTES), encoding="utf-8"
            )
            self.last_report = base.with_suffix(".html")

            self.update_ui(self.log, f"[+] Reports saved: {base}.html / .json / .csv / .txt")
            self.update_ui(self.refresh_dashboard, data)
            self.update_ui(self.finish_scan, "COMPLETE")
            if self.auto_open_var.get():
                webbrowser.open(self.last_report.as_uri())
        except Exception as error:
            self.update_ui(self.log, f"[ERROR] Could not create report: {error}")
            self.update_ui(self.finish_scan, "REPORT ERROR")
        finally:
            self._discard_current_xml()

    def _discard_current_xml(self):
        """Remove the temporary scan XML without masking the report error."""
        path = self.current_xml_path
        self.current_xml_path = None
        if path is None:
            return
        try:
            path.unlink(missing_ok=True)
        except OSError as error:
            self.update_ui(self.log, f"[ERROR] Could not remove temporary scan data: {error}")

    def enabled_options(self):
        """Return the active scan flags for display in reports."""
        options = []
        scan_type = self.scan_type.get()
        base_flag = SCAN_TYPES.get(scan_type, (None, None))[0]
        if base_flag:
            options.append(base_flag)
        timing = TIMING_TEMPLATES.get(self.timing_var.get())
        if timing:
            options.append(timing)
        state = self._checked_options()
        for key, flag in FLAG_LABELS.items():
            if state.get(key):
                options.append(flag)
        if not state.get("resolve_dns", True):
            options.append("-n")
        for key, flag in SCRIPT_LABELS.items():
            if state.get(key):
                options.append(flag)
        return options

    def assess_risk(self, records):
        """Return the shared risk decision plus the active severity color."""
        result = dict(assess(records))
        result["color"] = getattr(self, SEVERITY_ROLES[result["severity"]])
        return result

    def open_report(self):
        """Open the newest HTML report in the default browser."""
        if self.last_report and self.last_report.exists():
            webbrowser.open(self.last_report.as_uri())

    def export_report(self, extension):
        """Open the JSON/CSV/TXT companion of the latest report."""
        if not self.last_report:
            return
        path = self.last_report.with_suffix("." + extension)
        if path.exists():
            self.open_path(path)

    def open_path(self, path):
        """Open a file or folder with the operating system default handler."""
        path = Path(path)
        if not path.exists():
            messagebox.showinfo("NIGHTHAWK", f"Not found: {path}")
            return
        try:
            if os.name == "nt":
                os.startfile(str(path))
            else:
                webbrowser.open(path.resolve().as_uri())
        except OSError as error:
            messagebox.showerror("NIGHTHAWK", f"Could not open {path.name}: {error}")

    def recent_reports(self, limit=5):
        """Return the newest HTML reports with their parsed metadata."""
        if not REPORTS_DIR.exists():
            return []
        entries = []
        for path in sorted(REPORTS_DIR.glob("*.html"), key=lambda item: item.stat().st_mtime, reverse=True)[:limit]:
            target, created = "—", ""
            json_path = path.with_suffix(".json")
            if json_path.exists():
                try:
                    import json
                    payload = json.loads(json_path.read_text(encoding="utf-8"))
                    target = payload.get("target", "—")
                    created = payload.get("created", "").replace("T", " ")[:16]
                except (OSError, ValueError):
                    pass
            entries.append({"path": path, "target": target, "created": created})
        return entries

    def elapsed_seconds(self):
        """Seconds since the current scan started."""
        started = getattr(self, "scan_started_at", None)
        if started is None:
            return 0
        return max(0, int((datetime.datetime.now() - started).total_seconds()))
