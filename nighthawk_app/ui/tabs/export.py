"""Export tab: format cards, recent reports, and folder shortcuts."""

import tkinter as tk

from ...paths import REPORTS_DIR
from ..widgets import Panel, ScrollFrame, clear_children

FORMATS = (
    ("html", "HTML report", "Interactive dashboard with filters and a theme toggle."),
    ("json", "JSON data", "Complete machine-readable object for tooling."),
    ("csv", "CSV table", "Spreadsheet-friendly rows for every port."),
    ("txt", "Plain text", "One line per port for grep, diffs, and archiving."),
)


class ExportMixin:
    """Build and refresh the export workspace."""

    def build_export(self, tab):
        heading = tk.Frame(tab, bg=self.BG)
        heading.pack(fill=tk.X, padx=22, pady=(20, 6))
        tk.Label(heading, text="Reports & exports", bg=self.BG, fg=self.FG,
                 font=("Consolas", 16, "bold"), anchor="w").pack(fill=tk.X)
        tk.Label(heading, text="Every scan writes HTML, JSON, CSV, and TXT reports to the reports folder.",
                 bg=self.BG, fg=self.MUTED, font=("Segoe UI", 10), anchor="w").pack(fill=tk.X, pady=(3, 0))

        cards = tk.Frame(tab, bg=self.BG)
        cards.pack(fill=tk.X, padx=18, pady=(12, 4))
        for column in range(2):
            cards.grid_columnconfigure(column, weight=1, uniform="format")
        self.format_buttons = {}
        for index, (extension, title, description) in enumerate(FORMATS):
            card = Panel(cards, self, title=title)
            card.grid(row=index // 2, column=index % 2, sticky="nsew", padx=4, pady=4)
            tk.Label(card.body, text=description, bg=self.PANEL, fg=self.MUTED,
                     wraplength=360, justify=tk.LEFT, anchor="w",
                     font=("Segoe UI", 9)).pack(fill=tk.X, padx=15, pady=(11, 8))
            button = self.make_button(
                card.body, f"OPEN {extension.upper()}", lambda ext=extension: self.open_format(ext),
                "primary" if extension == "html" else "default",
                font=("Consolas", 8, "bold"), pady=6,
            )
            button.pack(anchor="w", padx=15, pady=(0, 12))
            self.format_buttons[extension] = button

        actions = tk.Frame(tab, bg=self.BG)
        actions.pack(side=tk.BOTTOM, fill=tk.X, padx=18, pady=(6, 16))
        self.make_button(actions, "OPEN REPORTS FOLDER", self.open_reports_folder, "ghost").pack(side=tk.LEFT)
        self.make_button(actions, "SCAN HISTORY & DIFF", self.show_history, "default").pack(
            side=tk.LEFT, padx=8)
        self.open_latest_btn = self.make_button(actions, "OPEN LATEST HTML", self.open_report, "primary")
        self.open_latest_btn.pack(side=tk.RIGHT)

        recent_panel = Panel(tab, self, title="Recent reports", subtitle="Latest five scans in the reports folder.")
        recent_panel.pack(fill=tk.BOTH, expand=True, padx=22, pady=(10, 6))
        self.recent_scroll = ScrollFrame(recent_panel.body, self)
        self.recent_scroll.pack(fill=tk.BOTH, expand=True, padx=10, pady=8)
        self.recent_frame = self.recent_scroll.body

        self.refresh_export()

    def open_format(self, extension):
        if not getattr(self, "last_report", None):
            self.set_status("NO REPORT YET", self.MUTED)
            return
        path = self.last_report.with_suffix("." + extension)
        if path.exists():
            self.open_path(path)

    def open_reports_folder(self):
        REPORTS_DIR.mkdir(exist_ok=True)
        self.open_path(REPORTS_DIR)

    def refresh_export(self):
        """Enable format buttons and rebuild the recent-report list."""
        if not hasattr(self, "format_buttons"):
            return
        enabled = bool(getattr(self, "last_report", None))
        for extension, button in self.format_buttons.items():
            button.config(state=tk.NORMAL if enabled else tk.DISABLED)
        if hasattr(self, "open_latest_btn"):
            self.open_latest_btn.config(state=tk.NORMAL if enabled else tk.DISABLED)
        clear_children(self.recent_frame)
        reports = self.recent_reports(5)
        if not reports:
            tk.Label(self.recent_frame, text="No reports yet. Run a scan to create one.",
                     bg=self.PANEL, fg=self.MUTED, font=("Segoe UI", 9)).pack(anchor="w", pady=8)
            return
        for report in reports:
            row = tk.Frame(self.recent_frame, bg=self.PANEL)
            row.pack(fill=tk.X, pady=1)
            tk.Label(row, text=report["target"], bg=self.PANEL, fg=self.FG,
                     font=("Consolas", 9), anchor="w").pack(side=tk.LEFT, padx=8, pady=6)
            tk.Label(row, text=report["created"] or "—", bg=self.PANEL, fg=self.MUTED,
                     font=("Consolas", 8), anchor="w").pack(side=tk.LEFT, padx=8)
            self.make_button(row, "OPEN", lambda path=report["path"]: self.open_path(path),
                             "ghost", font=("Consolas", 8, "bold"), pady=3).pack(side=tk.RIGHT, padx=6)
