"""NIGHTHAWK application shell: layout, tabs, shortcuts, and refresh flow."""

import tkinter as tk

from . import __version__
from .config import ConfigMixin
from .paths import logo_path
from .reports.report_mixin import ReportMixin
from .scanning.runner import ScanMixin
from .theme import ThemeMixin
from .ui.dialogs import DialogMixin
from .ui.header import HeaderMixin
from .ui.sidebar import SidebarMixin
from .ui.tabs.export import ExportMixin
from .ui.tabs.live import LiveMixin
from .ui.tabs.overview import OverviewMixin
from .ui.tabs.ports import PortsMixin
from .ui.tabs.scripts import ScriptsMixin
from .ui.widgets import MetricCard, TabBar, WidgetMixin


class NighthawkApp(
    ThemeMixin, ConfigMixin, WidgetMixin, HeaderMixin, SidebarMixin,
    OverviewMixin, PortsMixin, ScriptsMixin, LiveMixin, ExportMixin,
    DialogMixin, ScanMixin, ReportMixin,
):
    """The desktop application."""

    TAB_ITEMS = (
        ("overview", "Overview"),
        ("ports", "Ports & Services"),
        ("scripts", "Scripts"),
        ("live", "Live output"),
        ("export", "Export"),
    )

    def __init__(self, root):
        self.root = root
        self.config = self.load_config()
        self.dark = self.config.get("theme", "dark") != "light"
        self._apply_palette_attrs()
        self._themed_widgets = []

        self.is_scanning = False
        self.scan_process = None
        self.last_report = None
        self.last_scan_data = None
        self.last_command = ""
        self.current_xml_path = None
        self.live_host_info = {"mac": "Scanning...", "os": "Scanning..."}
        self.scan_started_at = None
        self.current_tab = None

        self.build_ui()
        self._bind_shortcuts()

    def build_ui(self):
        """Assemble the header, sidebar, metrics, tabs, and tab panels."""
        self.root.title(f"NIGHTHAWK {__version__} — Advanced Network Scanner")
        self.root.geometry("1530x960")
        self.root.minsize(1180, 780)
        self.root.configure(bg=self.BG)
        self.root.grid_rowconfigure(2, weight=1)
        self.root.grid_columnconfigure(0, weight=1)

        try:
            self.root.iconphoto(True, tk.PhotoImage(file=logo_path()))
        except tk.TclError:
            pass

        self._apply_ttk_styles()
        self.build_header(self.root)

        shell = tk.Frame(self.root, bg=self.BG)
        shell.grid(row=2, column=0, sticky="nsew", padx=12, pady=(10, 12))
        shell.grid_rowconfigure(0, weight=1)
        shell.grid_columnconfigure(1, weight=1)

        self.build_sidebar(shell)

        content = tk.Frame(shell, bg=self.BG)
        content.grid(row=0, column=1, sticky="nsew")
        content.grid_rowconfigure(3, weight=1)
        content.grid_columnconfigure(0, weight=1)

        self._build_heading(content)
        self._build_metrics(content)
        self._build_tabs(content)

        self.apply_theme()
        self.select_tab("overview")

    def _build_heading(self, content):
        heading = tk.Frame(content, bg=self.BG)
        heading.grid(row=0, column=0, sticky="ew", pady=(2, 10))
        heading.grid_columnconfigure(0, weight=1)
        self.report_title_var = tk.StringVar(value="Ready to scan")
        self.report_target_var = tk.StringVar(value="Choose a target in the scan panel and launch a scan.")
        tk.Label(heading, textvariable=self.report_title_var, bg=self.BG, fg=self.FG,
                 font=("Consolas", 20, "bold"), anchor="w").grid(row=0, column=0, sticky="w")
        tk.Label(heading, textvariable=self.report_target_var, bg=self.BG, fg=self.MUTED,
                 font=("Segoe UI", 11), anchor="w").grid(row=1, column=0, sticky="w", pady=(3, 0))
        self.status_label = tk.Label(heading, text="READY", bg=self.PANEL, fg=self.ACCENT,
                                     font=("Consolas", 9, "bold"), padx=14, pady=8,
                                     highlightbackground=self.BORDER, highlightthickness=1)
        self.status_label.grid(row=0, column=1, rowspan=2, sticky="e")

    def _build_metrics(self, content):
        cards = tk.Frame(content, bg=self.BG)
        cards.grid(row=1, column=0, sticky="ew", pady=(0, 12))
        for column in range(4):
            cards.grid_columnconfigure(column, weight=1)
        self.host_count_var = tk.StringVar(value="—")
        self.open_ports_var = tk.StringVar(value="—")
        self.findings_var = tk.StringVar(value="—")
        self.duration_var = tk.StringVar(value="—")
        specs = (
            ("Hosts up", self.host_count_var, self.HEALTHY, "reachable"),
            ("Open ports", self.open_ports_var, self.ACCENT, "exposed services"),
            ("Script findings", self.findings_var, self.MUTED, "NSE output"),
            ("Scan duration", self.duration_var, self.WARN, "elapsed"),
        )
        self.metric_cards = {}
        for column, (title, variable, color, caption) in enumerate(specs):
            card = MetricCard(cards, self, title, variable, color)
            card.set_caption(caption)
            card.grid(row=0, column=column, sticky="ew", padx=(0 if column == 0 else 8, 0))
            self.metric_cards[title] = card
        self.findings_card = self.metric_cards["Script findings"]

    def _build_tabs(self, content):
        holder = tk.Frame(content, bg=self.BG)
        holder.grid(row=2, column=0, sticky="ew")
        self.tabbar = TabBar(holder, self, self.TAB_ITEMS, self.select_tab)
        self.tabbar.pack(anchor="w")
        tk.Frame(holder, bg=self.BORDER, height=1).pack(fill=tk.X)

        container = tk.Frame(content, bg=self.BG)
        container.grid(row=3, column=0, sticky="nsew")
        container.grid_rowconfigure(0, weight=1)
        container.grid_columnconfigure(0, weight=1)

        builders = {
            "overview": self.build_overview,
            "ports": self.build_ports,
            "scripts": self.build_scripts,
            "live": self.build_live,
            "export": self.build_export,
        }
        self.tab_frames = {}
        for key, label in self.TAB_ITEMS:
            frame = tk.Frame(container, bg=self.BG)
            frame.grid(row=0, column=0, sticky="nsew")
            builders[key](frame)
            self.tab_frames[key] = frame

    def select_tab(self, key):
        """Raise one dashboard tab and update the tab bar."""
        if key not in getattr(self, "tab_frames", {}):
            return
        self.tab_frames[key].tkraise()
        self.current_tab = key
        if hasattr(self, "tabbar"):
            self.tabbar.set_active(key)
        if key == "export":
            self.refresh_export()

    def _bind_shortcuts(self):
        for index, (key, _label) in enumerate(self.TAB_ITEMS, start=1):
            self.root.bind(f"<Control-Key-{index}>", lambda _event, tab=key: self.select_tab(tab))
        self.root.bind("<Control-r>", lambda _event: self.start_scan())
        self.root.bind("<Control-period>", lambda _event: self.stop_scan())
        self.root.bind("<Control-t>", lambda _event: self.toggle_theme())
        self.root.bind("<Control-h>", lambda _event: self.show_history())
        self.root.bind("<Control-l>", self._focus_port_filter)

    def _focus_port_filter(self, _event=None):
        self.select_tab("ports")
        for child in self.tab_frames["ports"].winfo_children():
            if isinstance(child, tk.Frame):
                for grandchild in child.winfo_children():
                    if isinstance(grandchild, tk.Entry):
                        grandchild.focus_set()
                        return

    def update_ui(self, callback, *args, **kwargs):
        """Schedule a UI change safely from a background scan thread."""
        self.root.after(0, lambda: callback(*args, **kwargs))

    def refresh_dashboard(self, data):
        """Fill every tab from the newest scan."""
        records = data.get("results", [])
        current = [record for record in records if record.get("state") == "open"]
        findings = sum(len(record.get("scripts", [])) for record in records)

        self.report_title_var.set("Scan report")
        self.report_target_var.set(
            f"Target: {data.get('target', 'Unknown')}   ·   Ports: {data.get('ports', '—')}"
        )
        self.host_count_var.set(str(data.get("hosts_up", 1)))
        self.open_ports_var.set(str(len(current)))
        self.findings_var.set(str(findings))
        self.duration_var.set(data.get("duration", "—"))
        self.findings_card.set_color(self.ERROR if findings else self.MUTED)
        self.findings_card.set_caption(f"{findings} finding(s)")

        self.refresh_overview(data)
        self.refresh_ports(records)
        self.refresh_scripts(records)
        info = data.get("info", {})
        self.set_live_info(f"MAC: {info.get('mac', '---')}  |  OS: {info.get('os', '---')}")
        self.refresh_export()
        self.select_tab("overview")
