"""Overview tab: target facts, risk gauge, service mix, recommendations."""

import tkinter as tk

from ...reports.insights import all_scripts, open_ports, recommendations, service_mix
from ..widgets import Panel, clear_children

RISK_LEVELS = (
    ("CRITICAL", "CRITICAL"), ("HIGH", "ERROR"), ("REVIEW", "ORANGE"),
    ("EXPOSED", "WARN"), ("CLEAR", "HEALTHY"),
)


class OverviewMixin:
    """Build and refresh the overview dashboard."""

    INFO_KEYS = ("Target", "Port range", "MAC address", "Operating system",
                 "Network distance", "Nmap version", "Scan started", "Duration")

    def build_overview(self, tab):
        tab.grid_columnconfigure(0, weight=1, uniform="overview")
        tab.grid_columnconfigure(1, weight=1, uniform="overview")
        tab.grid_rowconfigure(0, weight=2)
        tab.grid_rowconfigure(1, weight=1)

        target_panel = Panel(tab, self, title="Target information")
        target_panel.grid(row=0, column=0, sticky="nsew", padx=(8, 4), pady=8)
        self.info_vars = {key: tk.StringVar(value="—") for key in self.INFO_KEYS}
        for index, (key, variable) in enumerate(self.info_vars.items()):
            row = tk.Frame(target_panel.body, bg=self.PANEL2 if index % 2 == 0 else self.PANEL)
            row.pack(fill=tk.X, padx=15, pady=1)
            tk.Label(row, text=key, width=18, anchor="w",
                     bg=row.cget("bg"), fg=self.MUTED,
                     font=("Segoe UI", 9)).pack(side=tk.LEFT, padx=8, pady=6)
            tk.Label(row, textvariable=variable, anchor="w", bg=row.cget("bg"), fg=self.FG,
                     font=("Consolas", 9)).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=8)
        target_panel.body.pack_configure(pady=(3, 3))

        risk_panel = Panel(tab, self, title="Risk assessment")
        risk_panel.grid(row=0, column=1, sticky="nsew", padx=(4, 8), pady=8)
        risk_body = tk.Frame(risk_panel.body, bg=self.PANEL)
        risk_body.pack(fill=tk.BOTH, expand=True, padx=8, pady=6)
        self.risk_canvas = tk.Canvas(risk_body, width=200, height=178, bg=self.PANEL,
                                     highlightthickness=0)
        self.risk_canvas.pack(side=tk.LEFT, padx=(4, 10))
        side = tk.Frame(risk_body, bg=self.PANEL)
        side.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.risk_label = tk.StringVar(value="AWAITING\nSCAN")
        self._risk_color = self.ACCENT
        self.risk_detail_var = tk.StringVar(value="Run a scan to assess open services and scripts.")
        tk.Label(side, textvariable=self.risk_detail_var, justify=tk.LEFT, anchor="w",
                 wraplength=270, bg=self.PANEL, fg=self.MUTED,
                 font=("Segoe UI", 9)).pack(anchor="w", pady=(6, 10))
        self.risk_legend = {}
        legend = tk.Frame(side, bg=self.PANEL)
        legend.pack(anchor="w")
        for label, role in RISK_LEVELS:
            chip = tk.Label(legend, text=label, bg=self.PANEL2, fg=getattr(self, role),
                            font=("Consolas", 7, "bold"), padx=6, pady=3,
                            highlightbackground=self.BORDER, highlightthickness=1)
            chip.pack(side=tk.LEFT, padx=(0, 4))
            self.risk_legend[label] = chip

        mix_panel = Panel(tab, self, title="Service mix")
        mix_panel.grid(row=1, column=0, sticky="nsew", padx=(8, 4), pady=(0, 8))
        self.mix_frame = tk.Frame(mix_panel.body, bg=self.PANEL)
        self.mix_frame.pack(fill=tk.BOTH, expand=True, padx=13, pady=12)

        rec_panel = Panel(tab, self, title="Recommendations")
        rec_panel.grid(row=1, column=1, sticky="nsew", padx=(4, 8), pady=(0, 8))
        self.recs_frame = tk.Frame(rec_panel.body, bg=self.PANEL)
        self.recs_frame.pack(fill=tk.BOTH, expand=True, padx=15, pady=10)

        actions = tk.Frame(tab, bg=self.BG)
        actions.grid(row=2, column=0, columnspan=2, sticky="ew", padx=8, pady=(0, 8))
        self.open_report_btn = self.make_button(actions, "OPEN HTML REPORT", self.open_report,
                                                "primary", state=tk.DISABLED)
        self.open_report_btn.pack(side=tk.LEFT)
        self.make_button(actions, "COPY SUMMARY", self.copy_summary, "default").pack(
            side=tk.LEFT, padx=8)
        self.make_button(actions, "RESCAN", self.start_scan, "ghost").pack(side=tk.LEFT)

        self._render_mix([])
        self._render_recommendations(["Run a scan to see recommendations for this host."])
        self.draw_risk(self.ACCENT)

    def draw_risk(self, color):
        """Draw the risk ring and label in the given severity color."""
        self._risk_color = color
        self.risk_canvas.delete("all")
        self.risk_canvas.create_oval(30, 10, 170, 150, outline=self.BORDER, width=9)
        self.risk_canvas.create_arc(30, 10, 170, 150, start=90, extent=270, style=tk.ARC,
                                    outline=color, width=9)
        self.risk_canvas.create_text(100, 68, text=self.risk_label.get(), fill=color,
                                     font=("Consolas", 11, "bold"), justify=tk.CENTER)
        self.risk_canvas.create_text(100, 106, text="assessment", fill=self.MUTED,
                                     font=("Consolas", 8), justify=tk.CENTER)

    def refresh_overview(self, data):
        """Update target facts, risk, service mix, and recommendations."""
        records = data.get("results", [])
        info = data.get("info", {})
        current = open_ports(records)
        scripts = all_scripts(records)
        values = {
            "Target": data.get("target", "Unknown"),
            "Port range": data.get("ports", "—"),
            "MAC address": info.get("mac", "Unknown"),
            "Operating system": info.get("os", "Unknown"),
            "Network distance": info.get("distance", "Unknown"),
            "Nmap version": data.get("nmap_version", "Unknown"),
            "Scan started": data.get("started", "—") or "—",
            "Duration": data.get("duration", "—"),
        }
        for key, value in values.items():
            self.info_vars[key].set(value)

        assessment = self.assess_risk(records)
        self._risk_severity = assessment["severity"]
        self.risk_label.set(assessment["label"].replace(" ", "\n"))
        self.draw_risk(assessment["color"])
        self.risk_detail_var.set(
            f"{assessment['detail']}\n{len(current)} open port(s) · {len(scripts)} script finding(s)"
        )
        for label, chip in self.risk_legend.items():
            active = label == assessment["label"].split()[0]
            chip.configure(bg=self.SELECT if active else self.PANEL2,
                           fg=getattr(self, dict(RISK_LEVELS)[label]) if active else self.MUTED)

        self._render_mix(service_mix(records))
        self._render_recommendations(recommendations(records))

    def _render_mix(self, mix):
        clear_children(self.mix_frame)
        if not mix:
            tk.Label(self.mix_frame, text="No services reported yet.", bg=self.PANEL,
                     fg=self.MUTED, font=("Segoe UI", 9)).pack(anchor="w")
            return
        for index, (name, count) in enumerate(mix):
            chip = tk.Frame(self.mix_frame, bg=self.PANEL2,
                            highlightbackground=self.BORDER, highlightthickness=1)
            chip.grid(row=index // 3, column=index % 3, sticky="w", padx=(0, 8), pady=(0, 8))
            tk.Label(chip, text=name, bg=self.PANEL2, fg=self.FG,
                     font=("Segoe UI", 9)).pack(side=tk.LEFT, padx=(9, 6), pady=6)
            tk.Label(chip, text=str(count), bg=self.PANEL2, fg=self.ACCENT,
                     font=("Consolas", 9, "bold")).pack(side=tk.LEFT, padx=(0, 9))

    def _render_recommendations(self, notes):
        clear_children(self.recs_frame)
        for note in notes:
            row = tk.Frame(self.recs_frame, bg=self.PANEL)
            row.pack(fill=tk.X, pady=3)
            tk.Label(row, text="▸", bg=self.PANEL, fg=self.ACCENT,
                     font=("Consolas", 9, "bold")).pack(side=tk.LEFT, anchor="n", padx=(0, 7))
            tk.Label(row, text=note, bg=self.PANEL, fg=self.MUTED, wraplength=420,
                     justify=tk.LEFT, anchor="w", font=("Segoe UI", 9)).pack(side=tk.LEFT, fill=tk.X)

    def copy_summary(self):
        """Copy a compact plain-text summary of the last scan."""
        data = getattr(self, "last_scan_data", None)
        if not data:
            self.set_status("NO SCAN TO COPY", self.MUTED)
            return
        records = data.get("results", [])
        assessment = self.assess_risk(records)
        summary = (
            f"NIGHTHAWK scan summary\n"
            f"Target: {data.get('target')}\n"
            f"Ports: {data.get('ports')}\n"
            f"Open ports: {len(open_ports(records))}\n"
            f"Script findings: {len(all_scripts(records))}\n"
            f"Risk: {assessment['label']} — {assessment['detail']}\n"
            f"Report: {self.last_report}\n"
        )
        self.root.clipboard_clear()
        self.root.clipboard_append(summary)
        self.set_status("SUMMARY COPIED", self.ACCENT)
