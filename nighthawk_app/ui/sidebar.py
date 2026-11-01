"""Left-hand scan configuration sidebar."""

import tkinter as tk
from tkinter import simpledialog, ttk

from ..scanning.options import (
    CHECK_GROUPS, PROFILES, SCAN_TYPES, TIMING_TEMPLATES, apply_port_preset_text,
)
from .widgets import CheckRow


class SidebarMixin:
    """Build and manage the scrollable scan form."""

    def build_sidebar(self, shell):
        self.sidebar = tk.Frame(shell, bg=self.PANEL, width=350,
                                highlightbackground=self.BORDER, highlightthickness=1)
        self.sidebar.grid(row=0, column=0, sticky="nsw", padx=(0, 12))
        self.sidebar.grid_propagate(False)

        actions = tk.Frame(self.sidebar, bg=self.PANEL)
        actions.pack(fill=tk.X, side=tk.BOTTOM, padx=15, pady=14)
        self.start_btn = self.make_button(actions, "▶  START SCAN", self.start_scan, "primary",
                                          font=("Consolas", 11, "bold"), pady=11)
        self.start_btn.pack(fill=tk.X)
        self.stop_btn = self.make_button(actions, "■  STOP", self.stop_scan, "danger", pady=6)
        self.stop_btn.config(state=tk.DISABLED)
        self.stop_btn.pack(fill=tk.X, pady=(6, 0))

        footer = tk.Frame(self.sidebar, bg=self.PANEL)
        footer.pack(side=tk.BOTTOM, fill=tk.X)
        tk.Frame(footer, bg=self.BORDER2, height=1).pack(fill=tk.X, padx=15, pady=(0, 5))
        self.scroll_hint = tk.Label(footer, text="SCROLL FOR MORE OPTIONS  ↓", bg=self.PANEL,
                                    fg=self.MUTED, font=("Consolas", 7), cursor="hand2")
        self.scroll_hint.pack(pady=(0, 5))
        self.scroll_hint.bind("<Button-1>", lambda _event: self.sidebar_canvas.yview_scroll(5, "units"))

        scroll_shell = tk.Frame(self.sidebar, bg=self.PANEL)
        scroll_shell.pack(fill=tk.BOTH, expand=True)
        self.sidebar_canvas = tk.Canvas(scroll_shell, bg=self.PANEL, highlightthickness=0, width=334)
        scrollbar = ttk.Scrollbar(scroll_shell, orient=tk.VERTICAL, command=self.sidebar_canvas.yview,
                                    style="Nighthawk.Vertical.TScrollbar")
        self.sidebar_canvas.configure(yscrollcommand=scrollbar.set)
        self.sidebar_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        inner = tk.Frame(self.sidebar_canvas, bg=self.PANEL)
        self.sidebar_inner = inner
        window = self.sidebar_canvas.create_window((0, 0), window=inner, anchor="nw")
        inner.bind("<Configure>", lambda event: self.sidebar_canvas.configure(
            scrollregion=self.sidebar_canvas.bbox("all")))
        self.sidebar_canvas.bind("<Configure>", lambda event: self.sidebar_canvas.itemconfigure(
            window, width=event.width))
        self.sidebar_canvas.bind("<Enter>", lambda event: self._bind_sidebar_wheel(True))
        self.sidebar_canvas.bind("<Leave>", lambda event: self._bind_sidebar_wheel(False))

        header = tk.Frame(inner, bg=self.PANEL)
        header.pack(fill=tk.X, padx=15, pady=(14, 4))
        tk.Label(header, text="SCAN CONFIGURATION", bg=self.PANEL, fg=self.MUTED,
                 font=("Consolas", 9, "bold"), anchor="w").pack(fill=tk.X)
        tk.Label(header, text="Target, ports, technique, and options.", bg=self.PANEL,
                 fg=self.MUTED, font=("Segoe UI", 8), anchor="w").pack(fill=tk.X, pady=(2, 0))

        form = tk.Frame(inner, bg=self.PANEL)
        form.pack(fill=tk.X, padx=15, pady=(6, 0))
        self.form = form

        self.profile_var = tk.StringVar(value=self.config.get("profile", "Custom / Manual"))
        self.profile_menu = self.make_menu(form, self.profile_var, list(PROFILES), self.apply_profile)
        self._form_field(form, "Profile", self.profile_menu)

        self.target_entry = self.make_entry(form, self.config.get("target", "127.0.0.1"))
        self._form_field(form, "Target", self.target_entry)

        self.port_entry = self.make_entry(form, self.config.get("ports", "1-1024"))
        self._form_field(form, "Port range", self.port_entry)
        self.port_dropdown = tk.StringVar(value="Custom")
        ports_menu = self.make_menu(form, self.port_dropdown,
                                    ["Custom", "Top 100", "Top 1000", "All"], self.apply_port_preset)
        ports_menu.pack(fill=tk.X, pady=(5, 0))

        self.scan_type = tk.StringVar(value=self.config.get("scan_type", "TCP Connect (-sT)"))
        scan_choices = [name for name in SCAN_TYPES if not name.startswith("---")]
        self.scan_menu = self.make_menu(form, self.scan_type, scan_choices, self.scan_type_changed)
        self._form_field(form, "Scan type", self.scan_menu)

        self.custom_frame = tk.Frame(form, bg=self.PANEL)
        self.custom_entry = self.make_entry(self.custom_frame, "-sT -sV --reason")
        self._form_field(self.custom_frame, "Custom flags", self.custom_entry)

        self.timing_var = tk.StringVar(value=self.config.get("timing", "Insane (T5)"))
        timing_menu = self.make_menu(form, self.timing_var, list(TIMING_TEMPLATES))
        self._form_field(form, "Timing", timing_menu)

        self.extra_entry = self.make_entry(form, self.config.get("extra_flags", "--reason"))
        self._form_field(form, "Extra flags", self.extra_entry)

        self.divider(inner).pack(fill=tk.X, padx=15, pady=(16, 4))

        self.check_vars = {}
        for group_title, entries in CHECK_GROUPS:
            tk.Label(inner, text=group_title, bg=self.PANEL, fg=self.ACCENT,
                     font=("Consolas", 8, "bold"), anchor="w").pack(fill=tk.X, padx=15, pady=(11, 3))
            for key, label, hint, default in entries:
                variable = tk.BooleanVar(value=bool(self.config.get(key, default)))
                self.check_vars[key] = variable
                row = CheckRow(inner, self, label, hint, variable)
                row.pack(fill=tk.X, padx=9)
                self.register_themed(row)

        self.divider(inner).pack(fill=tk.X, padx=15, pady=(13, 8))

        self.auto_open_var = tk.BooleanVar(value=bool(self.config.get("auto_open", True)))
        auto_row = CheckRow(inner, self, "Open report when complete",
                            "Launch the HTML report after each scan", self.auto_open_var)
        auto_row.pack(fill=tk.X, padx=9)
        self.register_themed(auto_row)

        tools = tk.Frame(inner, bg=self.PANEL)
        tools.pack(fill=tk.X, padx=15, pady=(10, 18))
        self.make_button(tools, "SAVE PRESET", self.save_favorite, "default",
                         font=("Consolas", 8, "bold"), pady=6).pack(
            side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 3))
        self.make_button(tools, "? CHEATSHEET", self.show_cheatsheet, "default",
                         font=("Consolas", 8, "bold"), pady=6).pack(
            side=tk.LEFT, fill=tk.X, expand=True, padx=(3, 0))

        self.favorites_menu = None
        self._refresh_favorites_menu(inner)

        self.sidebar_canvas.bind("<Configure>", lambda event: self._sync_sidebar_height())
        self.scan_type_changed(self.scan_type.get())

    def _form_field(self, parent, label, widget):
        self.field_label(parent, label).pack(fill=tk.X, pady=(10, 4))
        widget.pack(fill=tk.X)

    def _bind_sidebar_wheel(self, active):
        if active:
            self.sidebar_canvas.bind_all("<MouseWheel>", self._sidebar_wheel)
        else:
            self.sidebar_canvas.unbind_all("<MouseWheel>")

    def _sidebar_wheel(self, event):
        self.sidebar_canvas.yview_scroll(int(-event.delta / 120), "units")

    def _sync_sidebar_height(self):
        self.sidebar_canvas.configure(scrollregion=self.sidebar_canvas.bbox("all"))

    def _refresh_favorites_menu(self, parent):
        favorites = self.config.get("favorites", {})
        if self.favorites_menu is not None:
            self.favorites_menu.destroy()
            self.favorites_menu = None
        if not favorites:
            return
        self.favorite_var = tk.StringVar(value="Load saved preset…")
        self.favorites_menu = self.make_menu(parent, self.favorite_var,
                                             ["Load saved preset…"] + sorted(favorites),
                                             self.apply_favorite)
        self.favorites_menu.pack(fill=tk.X, padx=15, pady=(0, 14))

    def apply_profile(self, profile_name):
        """Apply a built-in profile to the form."""
        profile = PROFILES.get(profile_name)
        if not profile:
            return
        self.scan_type.set(profile["type"])
        self.timing_var.set(profile["timing"])
        self.port_dropdown.set(profile["ports"])
        self.apply_port_preset(profile["ports"])
        self.check_vars["service"].set(profile["service"])
        self.check_vars["os"].set(profile["os"])
        self.scan_type_changed(profile["type"])

    def apply_port_preset(self, preset):
        if preset == "Custom":
            return
        self.port_entry.delete(0, tk.END)
        self.port_entry.insert(0, apply_port_preset_text(preset))

    def scan_type_changed(self, selected):
        """Show the custom flags field only when the custom scan type is active."""
        if selected == "Custom Flags":
            if not self.custom_frame.winfo_manager():
                self.custom_frame.pack(fill=tk.X, after=self.scan_menu)
        else:
            self.custom_frame.pack_forget()

    def save_favorite(self):
        """Save the current form as a named local preset."""
        name = simpledialog.askstring("Save preset", "Name for this scan preset:", parent=self.root)
        if not name:
            return
        favorites = self.config.setdefault("favorites", {})
        favorites[name] = {
            "target": self.target_entry.get(),
            "ports": self.port_entry.get(),
            "scan_type": self.scan_type.get(),
            "timing": self.timing_var.get(),
            "extra_flags": self.extra_entry.get(),
            "auto_open": self.auto_open_var.get(),
            **{key: var.get() for key, var in self.check_vars.items()},
        }
        self.save_config()
        self._refresh_favorites_menu(self.sidebar_inner)
        self.set_status("PRESET SAVED", self.ACCENT)

    def apply_favorite(self, name):
        """Load a saved preset into the form."""
        favorite = self.config.get("favorites", {}).get(name)
        if not favorite:
            return
        self.target_entry.delete(0, tk.END)
        self.target_entry.insert(0, favorite.get("target", ""))
        self.port_entry.delete(0, tk.END)
        self.port_entry.insert(0, favorite.get("ports", ""))
        self.scan_type.set(favorite.get("scan_type", "TCP Connect (-sT)"))
        self.timing_var.set(favorite.get("timing", "Insane (T5)"))
        self.extra_entry.delete(0, tk.END)
        self.extra_entry.insert(0, favorite.get("extra_flags", ""))
        self.auto_open_var.set(bool(favorite.get("auto_open", True)))
        for key, variable in self.check_vars.items():
            if key in favorite:
                variable.set(bool(favorite[key]))
        self.favorite_var.set("Load saved preset…")
