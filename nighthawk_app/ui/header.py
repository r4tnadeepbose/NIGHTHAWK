"""Top header: brand, navigation, version chip, and theme control."""

import tkinter as tk

from .. import __version__, VERSION_LABEL
from ..paths import logo_path


class HeaderMixin:
    """Build the application header."""

    def build_header(self, root):
        header = tk.Frame(root, bg=self.BG, height=76)
        header.grid(row=0, column=0, sticky="ew")
        header.grid_columnconfigure(6, weight=1)

        try:
            self.logo_image = tk.PhotoImage(file=logo_path()).subsample(8, 8)
            tk.Label(header, image=self.logo_image, bg=self.BG).grid(
                row=0, column=0, padx=(12, 10), pady=6)
        except tk.TclError:
            tk.Label(header, text="N", bg=self.BG, fg=self.ACCENT,
                     font=("Consolas", 26, "bold")).grid(row=0, column=0, padx=(12, 10), pady=8)

        brand = tk.Frame(header, bg=self.BG)
        brand.grid(row=0, column=1, sticky="w")
        tk.Label(brand, text="NIGHTHAWK", bg=self.BG, fg=self.ACCENT,
                 font=("Consolas", 22, "bold")).pack(anchor="w")
        tk.Label(brand, text=f"ADVANCED NETWORK SCANNER  ·  {VERSION_LABEL}", bg=self.BG,
                 fg=self.MUTED, font=("Consolas", 8)).pack(anchor="w")

        nav = (
            ("Scan", lambda: self.select_tab("overview")),
            ("Reports", self.show_history),
            ("Settings", self.show_settings),
            ("About", self.show_about),
        )
        for index, (label, command) in enumerate(nav):
            active = label == "Scan"
            button = tk.Button(
                header, text=label.upper(), command=command, relief=tk.FLAT, bd=0,
                bg=self.PANEL3 if active else self.BG,
                fg=self.ACCENT if active else self.MUTED,
                activebackground=self.PANEL3, activeforeground=self.ACCENT,
                font=("Consolas", 9, "bold"), padx=18, pady=22, cursor="hand2",
            )
            button.grid(row=0, column=2 + index, sticky="ns", padx=(24 if index == 0 else 0, 0))

        version_chip = tk.Label(header, text=f"v{__version__}", bg=self.PANEL2, fg=self.MUTED,
                                font=("Consolas", 9, "bold"), padx=10, pady=6,
                                highlightbackground=self.BORDER, highlightthickness=1)
        version_chip.grid(row=0, column=7, padx=(0, 10))

        self.theme_btn = tk.Button(
            header, text="LIGHT", command=self.toggle_theme,
            bg=self.BG, fg=self.MUTED, activebackground=self.PANEL3,
            activeforeground=self.ACCENT, relief=tk.FLAT, bd=0,
            padx=14, pady=10, font=("Consolas", 9, "bold"),
            highlightbackground=self.BORDER, highlightthickness=1, cursor="hand2",
        )
        self.theme_btn.grid(row=0, column=8, padx=(0, 12))

        tk.Frame(root, bg=self.BORDER, height=1).grid(row=1, column=0, sticky="ew")
