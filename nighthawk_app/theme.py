"""Palettes, ttk styling, and live theme switching."""

import tkinter as tk
from tkinter import ttk

from .reports.risk import SEVERITY_ROLES

# Two coordinated themes. The dark side is a blue-charcoal terminal; the light
# side is a clean white surface with a faint rose tint and the same blue accent.
PALETTES = {
    "dark": {
        "BG": "#0d1116", "PANEL": "#141a21", "PANEL2": "#10161c",
        "PANEL3": "#1b232b", "BORDER": "#2a343d", "BORDER2": "#1d252c",
        "FG": "#d6dae0", "MUTED": "#8b949e", "ACCENT": "#7fa6c9",
        "ACCENT_HOVER": "#95b8d6", "WARN": "#c4a35f", "ERROR": "#b46a5e",
        "ORANGE": "#bd8a58", "CRITICAL": "#7b3a34", "HEALTHY": "#6fa6b3",
        "SELECT": "#22303c", "ON_ACCENT": "#0b1015",
    },
    "light": {
        "BG": "#f7f4f6", "PANEL": "#ffffff", "PANEL2": "#f7f3f6",
        "PANEL3": "#eae4e9", "BORDER": "#d9d2d9", "BORDER2": "#e8e2e7",
        "FG": "#232630", "MUTED": "#6b6f7c", "ACCENT": "#45688c",
        "ACCENT_HOVER": "#587fa5", "WARN": "#9a7526", "ERROR": "#a34f55",
        "ORANGE": "#a06b3f", "CRITICAL": "#6f3334", "HEALTHY": "#4f7d8a",
        "SELECT": "#e2e7f0", "ON_ACCENT": "#ffffff",
    },
}

# Colors from earlier releases are kept in the remap table so dialogs or
# user-facing text produced by older code still follow the active theme.
LEGACY_COLORS = {
    "#020b16": "BG", "#030d18": "PANEL2", "#05090c": "PANEL2",
    "#05111f": "PANEL", "#061321": "PANEL", "#06192c": "PANEL",
    "#071524": "PANEL", "#081a2b": "PANEL2", "#091d31": "PANEL2",
    "#0a2037": "PANEL3", "#0b2948": "PANEL3", "#0b3d70": "SELECT",
    "#101010": "PANEL2", "#123653": "BORDER", "#124f9a": "PANEL3",
    "#1260a8": "BORDER", "#1265df": "ACCENT", "#153b70": "SELECT",
    "#162b40": "PANEL3", "#164f96": "ACCENT_HOVER", "#1686ff": "ACCENT",
    "#19364a": "BORDER", "#1b4d78": "BORDER", "#1c4b74": "BORDER",
    "#202020": "PANEL3", "#240018": "PANEL2", "#27669c": "BORDER",
    "#25b9ff": "ACCENT", "#28536a": "BORDER", "#2b3540": "BORDER",
    "#333333": "BORDER", "#3d1231": "PANEL3", "#3ddc97": "HEALTHY",
    "#42e692": "HEALTHY", "#47caff": "ACCENT", "#4ca7ff": "ACCENT",
    "#4fd7ff": "ACCENT", "#4fe2e0": "ACCENT", "#52e99a": "HEALTHY",
    "#57ed9f": "HEALTHY", "#5e94c8": "MUTED", "#5f82a6": "MUTED",
    "#75c6ff": "ACCENT", "#78a5d2": "MUTED", "#82a9d7": "MUTED",
    "#88aaca": "MUTED", "#8e9baa": "MUTED", "#8fb4d8": "MUTED",
    "#914187": "BORDER", "#91b2d3": "MUTED", "#9bbad8": "MUTED",
    "#9eb9d8": "MUTED", "#9fc2e5": "MUTED", "#9fc9f4": "MUTED",
    "#b7d4ef": "FG", "#b9d8ff": "FG", "#b9ddff": "FG",
    "#bcd7ff": "FG", "#bfd8f3": "FG", "#c8ddf4": "FG",
    "#c8e0ff": "FG", "#c8e2ff": "FG", "#d7e9ff": "FG",
    "#d9eaff": "FG", "#e1efff": "FG", "#e3f2ff": "FG",
    "#e6f2ff": "FG", "#ec3545": "ACCENT", "#f2c8ed": "ACCENT",
    "#ff5c65": "ACCENT_HOVER", "#ff6b6b": "ERROR",
}


class ThemeMixin:
    """Palette attributes, theme persistence, and widget recoloring."""

    PALETTES = PALETTES

    BG = PALETTES["dark"]["BG"]
    PANEL = PALETTES["dark"]["PANEL"]
    PANEL2 = PALETTES["dark"]["PANEL2"]
    PANEL3 = PALETTES["dark"]["PANEL3"]
    BORDER = PALETTES["dark"]["BORDER"]
    BORDER2 = PALETTES["dark"]["BORDER2"]
    FG = PALETTES["dark"]["FG"]
    MUTED = PALETTES["dark"]["MUTED"]
    ACCENT = PALETTES["dark"]["ACCENT"]
    ACCENT_HOVER = PALETTES["dark"]["ACCENT_HOVER"]
    WARN = PALETTES["dark"]["WARN"]
    ERROR = PALETTES["dark"]["ERROR"]
    ORANGE = PALETTES["dark"]["ORANGE"]
    CRITICAL = PALETTES["dark"]["CRITICAL"]
    HEALTHY = PALETTES["dark"]["HEALTHY"]
    SELECT = PALETTES["dark"]["SELECT"]
    ON_ACCENT = PALETTES["dark"]["ON_ACCENT"]

    def _apply_palette_attrs(self):
        """Copy the active palette onto the app for convenient attribute access."""
        for key, value in self.PALETTES["dark" if self.dark else "light"].items():
            setattr(self, key, value)

    def toggle_theme(self):
        """Flip the palette, repaint every themed surface, and save the choice."""
        self.dark = not self.dark
        self._apply_palette_attrs()
        self.apply_theme()
        self.config["theme"] = "dark" if self.dark else "light"
        self.save_config()
        if hasattr(self, "theme_btn"):
            self.theme_btn.configure(text="LIGHT" if self.dark else "DARK")

    def register_themed(self, widget):
        """Register a custom widget that repaints itself on theme changes."""
        if not hasattr(self, "_themed_widgets"):
            self._themed_widgets = []
        self._themed_widgets.append(widget)
        return widget

    def apply_theme(self):
        """Recolor the whole window, ttk styles, custom widgets, and tags."""
        self.root.configure(bg=self.BG)
        mapping = self._theme_color_map()
        self._recolor_tree(self.root, mapping)
        for child in self.root.winfo_children():
            if isinstance(child, tk.Toplevel):
                self._recolor_tree(child, mapping)
                self._restyle_text_tags(child)
        self._apply_ttk_styles()
        for widget in getattr(self, "_themed_widgets", []):
            try:
                widget.apply_theme()
            except tk.TclError:
                pass
        if hasattr(self, "risk_canvas") and hasattr(self, "_risk_color"):
            severity = getattr(self, "_risk_severity", None)
            color = getattr(self, SEVERITY_ROLES[severity]) if severity else self.ACCENT
            self._risk_color = color
            self.draw_risk(color)
        for attr in ("output", "port_table"):
            widget = getattr(self, attr, None)
            if widget is None:
                continue
            setter = getattr(widget, "tag_configure", None) or getattr(widget, "tag_config", None)
            for name, color in (("open", self.HEALTHY), ("closed", self.WARN), ("error", self.ERROR)):
                try:
                    setter(name, foreground=color)
                except tk.TclError:
                    pass
        if hasattr(self, "theme_btn"):
            self.theme_btn.configure(
                bg=self.BG, fg=self.MUTED,
                activebackground=self.PANEL3, activeforeground=self.ACCENT,
                highlightbackground=self.BORDER,
                text="LIGHT" if self.dark else "DARK",
            )

    def _apply_ttk_styles(self):
        """Configure tree views, scrollbars, and the progress bar."""
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure("Nighthawk.Horizontal.TProgressbar", troughcolor=self.BG,
                        background=self.ACCENT, bordercolor=self.PANEL2,
                        lightcolor=self.ACCENT, darkcolor=self.ACCENT)
        style.configure("Nighthawk.Treeview", background=self.PANEL, fieldbackground=self.PANEL,
                        foreground=self.FG, rowheight=30, borderwidth=0,
                        font=("Consolas", 10))
        style.configure("Nighthawk.Treeview.Heading", background=self.PANEL3, foreground=self.MUTED,
                        font=("Consolas", 9, "bold"), relief=tk.FLAT, borderwidth=0)
        style.map("Nighthawk.Treeview",
                  background=[("selected", self.SELECT)],
                  foreground=[("selected", self.ACCENT)])
        for orient in ("Vertical", "Horizontal"):
            style.configure(f"Nighthawk.{orient}.TScrollbar", background=self.PANEL3,
                            troughcolor=self.PANEL2, bordercolor=self.PANEL2,
                            arrowcolor=self.MUTED, lightcolor=self.PANEL3,
                            darkcolor=self.PANEL3, arrowsize=0, width=10)

    def _theme_color_map(self):
        """Map every known palette/legacy color to the active palette color."""
        roles = {}
        for theme in self.PALETTES.values():
            for role, value in theme.items():
                roles[value.lower()] = role
        roles.update(LEGACY_COLORS)
        return {source: getattr(self, role) for source, role in roles.items()}

    def _recolor_tree(self, widget, mapping):
        """Recursively remap background/foreground colors on one widget subtree."""
        for option in ("background", "foreground", "activebackground", "activeforeground",
                       "insertbackground", "highlightbackground", "highlightcolor",
                       "selectcolor", "selectbackground", "selectforeground",
                       "troughcolor", "disabledforeground"):
            try:
                current = str(widget.cget(option)).lower()
                if current in mapping:
                    widget.configure(**{option: mapping[current]})
            except tk.TclError:
                pass
        for child in widget.winfo_children():
            self._recolor_tree(child, mapping)

    def _apply_theme_to(self, window):
        """Apply the active palette to a freshly created dialog."""
        self._recolor_tree(window, self._theme_color_map())
        self._restyle_text_tags(window)
        for widget in getattr(self, "_themed_widgets", []):
            try:
                widget.apply_theme()
            except tk.TclError:
                pass

    def _restyle_text_tags(self, widget):
        """Update semantic text tags after a theme switch."""
        tag_colors = {"added": self.HEALTHY, "removed": self.ERROR,
                      "heading": self.ACCENT, "muted": self.MUTED,
                      "open": self.HEALTHY, "closed": self.WARN, "error": self.ERROR}
        if isinstance(widget, tk.Text):
            names = set(widget.tag_names())
            for tag, color in tag_colors.items():
                if tag in names:
                    widget.tag_config(tag, foreground=color)
        for child in widget.winfo_children():
            self._restyle_text_tags(child)
