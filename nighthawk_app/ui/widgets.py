"""Reusable, theme-aware dashboard widgets."""

import tkinter as tk
from tkinter import ttk


def clear_children(widget):
    """Destroy every child so a panel can be rebuilt."""
    for child in widget.winfo_children():
        child.destroy()


class CheckRow(tk.Frame):
    """A full-row checkbox with a drawn square indicator and a hint line."""

    def __init__(self, parent, app, label, hint, variable):
        super().__init__(parent, bg=app.PANEL, cursor="hand2", takefocus=1,
                         highlightthickness=1, highlightbackground=app.PANEL)
        self.app = app
        self.variable = variable
        self.hint_text = hint
        self.focused = False

        self.canvas = tk.Canvas(self, width=18, height=18, highlightthickness=0, bg=app.PANEL)
        self.canvas.grid(row=0, column=0, rowspan=2, sticky="n", padx=(10, 9), pady=(8, 6))
        self.label = tk.Label(self, text=label, bg=app.PANEL, fg=app.FG,
                              font=("Segoe UI", 9), anchor="w")
        self.label.grid(row=0, column=1, sticky="ew", pady=(7, 0), padx=(0, 10))
        self.hint = tk.Label(self, text=hint, bg=app.PANEL, fg=app.MUTED,
                             font=("Consolas", 7), anchor="w")
        self.hint.grid(row=1, column=1, sticky="ew", pady=(0, 6), padx=(0, 10))
        self.grid_columnconfigure(1, weight=1)

        for widget in (self, self.canvas, self.label, self.hint):
            widget.bind("<Button-1>", self._toggle)
            widget.bind("<Enter>", self._hover_on)
            widget.bind("<Leave>", self._hover_off)
        self.bind("<space>", self._toggle)
        self.bind("<Return>", self._toggle)
        self.bind("<FocusIn>", self._focus_on)
        self.bind("<FocusOut>", self._focus_off)
        variable.trace_add("write", lambda *_: self._draw())
        self._draw()

    def _toggle(self, _event=None):
        self.variable.set(not self.variable.get())
        return "break"

    def _hover_on(self, _event=None):
        self.configure(highlightbackground=self.app.BORDER, bg=self.app.PANEL3)
        for widget in (self.canvas, self.label, self.hint):
            widget.configure(bg=self.app.PANEL3)
        self._draw()

    def _hover_off(self, _event=None):
        self._paint_background()
        self._draw()

    def _focus_on(self, _event=None):
        self.focused = True
        self._draw()

    def _focus_off(self, _event=None):
        self.focused = False
        self._draw()

    def _paint_background(self):
        self.configure(bg=self.app.PANEL, highlightbackground=self.app.PANEL)
        for widget in (self.canvas, self.label, self.hint):
            widget.configure(bg=self.app.PANEL)

    def _draw(self):
        app = self.app
        self.canvas.delete("all")
        on = self.variable.get()
        outline = app.ACCENT if (on or self.focused) else app.BORDER
        self.canvas.create_rectangle(2, 2, 16, 16, outline=outline, width=2, fill=app.PANEL2)
        if on:
            self.canvas.create_line(5, 9, 8, 12, 13, 5, fill=app.ACCENT, width=2,
                                    capstyle="round", joinstyle="round")
        self.label.configure(fg=app.ACCENT if on else app.FG)
        if self.focused:
            self.configure(highlightbackground=app.ACCENT)
        else:
            self.configure(highlightbackground=app.PANEL)

    def apply_theme(self):
        self._paint_background()
        self.label.configure(font=("Segoe UI", 9))
        self._draw()


class TabBar(tk.Frame):
    """Button-style dashboard tabs with counts and an accent underline."""

    def __init__(self, parent, app, items, command):
        super().__init__(parent, bg=app.BG)
        self.app = app
        self.command = command
        self.labels = dict(items)
        self.buttons = {}
        self.holders = {}
        self.underlines = {}
        self.counts = {}
        self.active = None
        for key, label in items:
            holder = tk.Frame(self, bg=app.BG)
            holder.pack(side=tk.LEFT, padx=(0, 2))
            button = tk.Button(holder, text=label.upper(), command=lambda k=key: command(k),
                               bg=app.BG, fg=app.MUTED, activebackground=app.PANEL3,
                               activeforeground=app.ACCENT, relief=tk.FLAT, bd=0,
                               font=("Consolas", 9, "bold"), padx=18, pady=10, cursor="hand2")
            button.pack(fill=tk.X)
            line = tk.Frame(holder, bg=app.BG, height=2)
            line.pack(fill=tk.X)
            self.buttons[key] = button
            self.holders[key] = holder
            self.underlines[key] = line
            self.counts[key] = 0
        if items:
            self.set_active(items[0][0])

    def _text(self, key):
        label = self.labels[key].upper()
        count = self.counts.get(key) or 0
        return f"{label}  {count}" if count else label

    def set_count(self, key, count):
        self.counts[key] = count
        self.buttons[key].configure(text=self._text(key))

    def set_active(self, key):
        self.active = key
        for name, button in self.buttons.items():
            selected = name == key
            button.configure(
                bg=self.app.PANEL if selected else self.app.BG,
                fg=self.app.ACCENT if selected else self.app.MUTED,
                activebackground=self.app.PANEL3,
                activeforeground=self.app.ACCENT,
            )
            self.underlines[name].configure(bg=self.app.ACCENT if selected else self.app.BG)

    def apply_theme(self):
        self.configure(bg=self.app.BG)
        for holder in self.holders.values():
            holder.configure(bg=self.app.BG)
        if self.active:
            self.set_active(self.active)
        else:
            for button in self.buttons.values():
                button.configure(bg=self.app.BG, fg=self.app.MUTED,
                                 activebackground=self.app.PANEL3,
                                 activeforeground=self.app.ACCENT)


class ScrollFrame(tk.Frame):
    """A canvas-backed scroll area that keeps its content theme-aware."""

    def __init__(self, parent, app, bg=None):
        background = bg or app.PANEL
        super().__init__(parent, bg=background)
        self.app = app
        self.canvas = tk.Canvas(self, bg=background, highlightthickness=0)
        self.scrollbar = ttk.Scrollbar(self, orient=tk.VERTICAL, command=self.canvas.yview,
                                       style="Nighthawk.Vertical.TScrollbar")
        self.canvas.configure(yscrollcommand=self.scrollbar.set)
        self.canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.body = tk.Frame(self.canvas, bg=background)
        window = self.canvas.create_window((0, 0), window=self.body, anchor="nw")
        self.body.bind("<Configure>", lambda event: self.canvas.configure(
            scrollregion=self.canvas.bbox("all")))
        self.canvas.bind("<Configure>", lambda event: self.canvas.itemconfigure(
            window, width=event.width))
        self.canvas.bind("<Enter>", lambda event: self.canvas.bind_all("<MouseWheel>", self._wheel))
        self.canvas.bind("<Leave>", lambda event: self.canvas.unbind_all("<MouseWheel>"))

    def _wheel(self, event):
        self.canvas.yview_scroll(int(-event.delta / 120), "units")


class MetricCard(tk.Frame):
    """Compact KPI card with a caption and a large value."""

    def __init__(self, parent, app, title, variable, color):
        super().__init__(parent, bg=app.PANEL, highlightbackground=app.BORDER, highlightthickness=1)
        self.app = app
        self.variable = variable
        tk.Label(self, text=title.upper(), bg=app.PANEL, fg=app.MUTED,
                 font=("Consolas", 8, "bold"), anchor="w").pack(fill=tk.X, padx=15, pady=(11, 1))
        self.value = tk.Label(self, textvariable=variable, bg=app.PANEL, fg=color,
                              font=("Consolas", 19, "bold"), anchor="w")
        self.value.pack(fill=tk.X, padx=15, pady=(0, 11))
        self.color = color
        self.caption = None

    def set_caption(self, text):
        if self.caption is None:
            self.caption = tk.Label(self, text=text, bg=self.app.PANEL, fg=self.app.MUTED,
                                    font=("Consolas", 7), anchor="w")
            self.caption.pack(fill=tk.X, padx=15, pady=(0, 9))
        else:
            self.caption.config(text=text)

    def set_color(self, color):
        self.color = color
        self.value.configure(fg=color)


class Panel(tk.Frame):
    """Bordered surface with an optional uppercase section heading."""

    def __init__(self, parent, app, title=None, subtitle=None):
        super().__init__(parent, bg=app.PANEL, highlightbackground=app.BORDER, highlightthickness=1)
        self.app = app
        if title:
            header = tk.Frame(self, bg=app.PANEL)
            header.pack(fill=tk.X)
            tk.Label(header, text=title.upper(), bg=app.PANEL, fg=app.MUTED,
                     font=("Consolas", 9, "bold"), anchor="w").pack(fill=tk.X, padx=15, pady=(12, 5 if subtitle else 9))
            if subtitle:
                tk.Label(header, text=subtitle, bg=app.PANEL, fg=app.MUTED,
                         font=("Segoe UI", 9), anchor="w").pack(fill=tk.X, padx=15, pady=(0, 9))
            tk.Frame(self, bg=app.BORDER2, height=1).pack(fill=tk.X)
        self.body = tk.Frame(self, bg=app.PANEL)
        self.body.pack(fill=tk.BOTH, expand=True)


class WidgetMixin:
    """Small factory helpers used by the header, sidebar, and tabs."""

    def make_button(self, parent, text, command, kind="default", **kwargs):
        """Create a flat button in one of the theme roles."""
        if kind == "primary":
            colors = dict(bg=self.ACCENT, fg=self.ON_ACCENT,
                          activebackground=self.ACCENT_HOVER, activeforeground=self.ON_ACCENT)
        elif kind == "ghost":
            colors = dict(bg=self.BG, fg=self.MUTED,
                          activebackground=self.PANEL3, activeforeground=self.ACCENT)
        elif kind == "danger":
            colors = dict(bg=self.PANEL3, fg=self.ERROR,
                          activebackground=self.SELECT, activeforeground=self.ERROR)
        else:
            colors = dict(bg=self.PANEL3, fg=self.FG,
                          activebackground=self.SELECT, activeforeground=self.ACCENT)
        return tk.Button(parent, text=text, command=command, relief=tk.FLAT, bd=0,
                         font=kwargs.pop("font", ("Consolas", 9, "bold")),
                         padx=kwargs.pop("padx", 12), pady=kwargs.pop("pady", 8),
                         cursor="hand2", **colors, **kwargs)

    def make_entry(self, parent, value="", width=None):
        """Create a themed single-line entry."""
        entry = tk.Entry(parent, bg=self.PANEL2, fg=self.FG, insertbackground=self.ACCENT,
                         relief=tk.FLAT, highlightthickness=1, highlightbackground=self.BORDER,
                         highlightcolor=self.ACCENT, font=("Consolas", 10))
        if width:
            entry.configure(width=width)
        entry.insert(0, value)
        return entry

    def make_menu(self, parent, variable, values, command=None):
        """Create a themed option menu."""
        menu = tk.OptionMenu(parent, variable, *values, command=command)
        menu.config(bg=self.PANEL2, fg=self.FG, activebackground=self.PANEL3,
                    activeforeground=self.ACCENT, relief=tk.FLAT, highlightthickness=1,
                    highlightbackground=self.BORDER, anchor="w", font=("Consolas", 9), padx=9)
        menu["menu"].config(bg=self.PANEL2, fg=self.FG, activebackground=self.PANEL3,
                            activeforeground=self.ACCENT, font=("Consolas", 9))
        return menu

    def field_label(self, parent, text):
        """Return a small uppercase field label."""
        return tk.Label(parent, text=text, bg=self.PANEL, fg=self.MUTED,
                        font=("Consolas", 8, "bold"), anchor="w")

    def hint(self, parent, text):
        """Return a dim helper line."""
        return tk.Label(parent, text=text, bg=self.PANEL, fg=self.MUTED,
                        font=("Segoe UI", 8), anchor="w", justify=tk.LEFT)

    def divider(self, parent, bg_role="BORDER2"):
        """Return a one-pixel divider frame."""
        return tk.Frame(parent, bg=getattr(self, bg_role), height=1)
