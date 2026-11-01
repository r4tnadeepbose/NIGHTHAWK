"""Script output tab: findings list, detail viewer, search, and copy."""

import tkinter as tk
from tkinter import ttk

from ...reports.insights import all_scripts
from ..widgets import Panel


class ScriptsMixin:
    """Browse NSE findings without leaving the dashboard."""

    def build_scripts(self, tab):
        self.script_findings = []
        top = tk.Frame(tab, bg=self.BG)
        top.pack(fill=tk.X, padx=8, pady=(8, 6))
        tk.Label(top, text="FILTER", bg=self.BG, fg=self.MUTED,
                 font=("Consolas", 8, "bold")).pack(side=tk.LEFT, padx=(0, 8))
        self.script_filter_var = tk.StringVar()
        search = self.make_entry(top, "")
        search.configure(textvariable=self.script_filter_var)
        search.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.script_filter_var.trace_add("write", lambda *_: self._apply_script_filter())
        self.script_count_var = tk.StringVar(value="No findings")
        tk.Label(top, textvariable=self.script_count_var, bg=self.BG, fg=self.MUTED,
                 font=("Consolas", 8)).pack(side=tk.LEFT, padx=10)
        self.make_button(top, "COPY FINDING", self.copy_script, "default",
                         font=("Consolas", 8, "bold"), pady=6).pack(side=tk.LEFT)

        panes = tk.PanedWindow(tab, orient=tk.HORIZONTAL, sashwidth=6, bg=self.BG, bd=0,
                               sashrelief=tk.FLAT)
        panes.pack(fill=tk.BOTH, expand=True, padx=8, pady=(0, 8))
        left = Panel(panes, self)
        right = Panel(panes, self)
        panes.add(left, minsize=320)
        panes.add(right, minsize=360)

        self.script_tree = ttk.Treeview(left.body, columns=("port", "script", "summary"),
                                        show="headings", style="Nighthawk.Treeview")
        for key, title, width in (("port", "PORT", 90), ("script", "SCRIPT", 150),
                                  ("summary", "SUMMARY", 240)):
            self.script_tree.heading(key, text=title)
            self.script_tree.column(key, width=width, anchor="w")
        self.script_tree.pack(fill=tk.BOTH, expand=True, padx=1, pady=1)
        self.script_tree.bind("<<TreeviewSelect>>", lambda _event: self._show_script())

        tk.Label(right.body, text="FINDING DETAIL", bg=self.PANEL, fg=self.MUTED,
                 font=("Consolas", 8, "bold"), anchor="w").pack(fill=tk.X, padx=12, pady=(10, 5))
        self.script_detail = tk.Text(right.body, state=tk.DISABLED, bg=self.PANEL2, fg=self.FG,
                                     relief=tk.FLAT, wrap=tk.WORD, font=("Consolas", 9),
                                     padx=12, pady=10, highlightthickness=0)
        self.script_detail.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))

    def refresh_scripts(self, records):
        """Rebuild the findings list from the latest scan."""
        self.script_findings = all_scripts(records)
        if hasattr(self, "tabbar"):
            self.tabbar.set_count("scripts", len(self.script_findings))
        self.script_count_var.set(f"{len(self.script_findings)} finding(s)")
        self._apply_script_filter()

    def _apply_script_filter(self):
        if not hasattr(self, "script_tree"):
            return
        query = self.script_filter_var.get().strip().lower() if hasattr(self, "script_filter_var") else ""
        for item in self.script_tree.get_children():
            self.script_tree.delete(item)
        visible = 0
        for index, finding in enumerate(self.script_findings):
            text = f"{finding['port']}/{finding['protocol']} {finding['id']} {finding.get('output', '')}"
            if query and query not in text.lower():
                continue
            summary = " ".join(str(finding.get("output", "")).split())[:90] or "—"
            self.script_tree.insert("", tk.END, iid=str(index),
                                    values=(f"{finding['port']}/{finding['protocol']}",
                                            finding["id"], summary))
            visible += 1
        if not visible:
            self.script_tree.insert("", tk.END, values=("—", "no matches", "—"))
        children = self.script_tree.get_children()
        if children and self.script_tree.item(children[0], "values")[1] not in ("no matches", "no findings"):
            self.script_tree.selection_set(children[0])
        else:
            message = ("No findings match the filter." if self.script_findings
                       else "No Nmap script output was returned for this scan.")
            self._set_script_detail(message)

    def _show_script(self):
        selection = self.script_tree.selection()
        if not selection:
            return
        try:
            finding = self.script_findings[int(selection[0])]
        except (ValueError, IndexError):
            return
        self._set_script_detail(f"[{finding['id']}]  {finding['port']}/{finding['protocol']}\n\n"
                                f"{finding.get('output', '')}")

    def _set_script_detail(self, text):
        self.script_detail.config(state=tk.NORMAL)
        self.script_detail.delete("1.0", tk.END)
        self.script_detail.insert(tk.END, text)
        self.script_detail.config(state=tk.DISABLED)

    def copy_script(self):
        """Copy the visible finding detail to the clipboard."""
        text = self.script_detail.get("1.0", tk.END).strip()
        if not text:
            self.set_status("NO FINDING TO COPY", self.MUTED)
            return
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        self.set_status("FINDING COPIED", self.ACCENT)
