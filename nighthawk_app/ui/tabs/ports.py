"""Ports & Services tab: filtering, sorting, copying, and counts."""

import tkinter as tk
from tkinter import ttk

from ...reports.insights import open_ports, possibly_open_ports, version_label


class PortsMixin:
    """Build and refresh the port results table."""

    STATES = ("All states", "Open", "Open|filtered", "Filtered", "Closed")

    def build_ports(self, tab):
        self.port_records = []
        self._port_sort_key = "port"
        self._port_sort_reverse = False

        toolbar = tk.Frame(tab, bg=self.BG)
        toolbar.pack(fill=tk.X, padx=8, pady=(8, 6))
        tk.Label(toolbar, text="FILTER", bg=self.BG, fg=self.MUTED,
                 font=("Consolas", 8, "bold")).pack(side=tk.LEFT, padx=(0, 8))
        self.port_filter_var = tk.StringVar()
        search = self.make_entry(toolbar, "")
        search.configure(textvariable=self.port_filter_var)
        search.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.port_filter_var.trace_add("write", lambda *_: self._apply_port_filters())
        self.port_filter_var.set("")

        self.port_state_var = tk.StringVar(value="All states")
        self.make_menu(toolbar, self.port_state_var, self.STATES,
                       lambda _value: self._apply_port_filters()).pack(side=tk.LEFT, padx=(8, 0))
        self.make_button(toolbar, "COPY ROW", self.copy_selected_port, "default",
                         font=("Consolas", 8, "bold"), pady=6).pack(side=tk.LEFT, padx=(8, 0))

        self.port_counts_var = tk.StringVar(value="No scan loaded")
        tk.Label(tab, textvariable=self.port_counts_var, bg=self.BG, fg=self.MUTED,
                 font=("Consolas", 8), anchor="w").pack(fill=tk.X, padx=14, pady=(0, 4))

        columns = ("host", "port", "state", "service", "version", "reason")
        self.port_table = ttk.Treeview(tab, columns=columns, show="headings",
                                       style="Nighthawk.Treeview", selectmode="browse")
        for name, title, width in (("host", "HOST", 150), ("port", "PORT", 100),
                                   ("state", "STATE", 110), ("service", "SERVICE", 140),
                                   ("version", "VERSION", 300), ("reason", "REASON", 140)):
            self.port_table.heading(name, text=title, command=lambda key=name: self.sort_ports(key))
            self.port_table.column(name, width=width, anchor="w")
        self.port_table.pack(fill=tk.BOTH, expand=True, padx=8, pady=(0, 8))
        self.port_table.tag_configure("open", foreground=self.HEALTHY)
        self.port_table.tag_configure("filtered", foreground=self.WARN)
        self.port_table.tag_configure("closed", foreground=self.ERROR)
        self.port_table.bind("<Double-1>", lambda _event: self.copy_selected_port())
        self._update_port_headings()

    def refresh_ports(self, records):
        """Store scan data and rebuild the filtered table."""
        self.port_records = list(records)
        current = len(open_ports(self.port_records))
        if hasattr(self, "tabbar"):
            self.tabbar.set_count("ports", current)
        self._apply_port_filters()

    def sort_ports(self, key):
        """Sort the table by a column, toggling direction when repeated."""
        if key == self._port_sort_key:
            self._port_sort_reverse = not self._port_sort_reverse
        else:
            self._port_sort_key = key
            self._port_sort_reverse = False
        self._update_port_headings()
        self._apply_port_filters()

    def _update_port_headings(self):
        titles = {"host": "HOST", "port": "PORT", "state": "STATE", "service": "SERVICE",
                  "version": "VERSION", "reason": "REASON"}
        arrow = "▼" if self._port_sort_reverse else "▲"
        for key, title in titles.items():
            suffix = f" {arrow}" if key == self._port_sort_key else ""
            self.port_table.heading(key, text=title + suffix)

    def _apply_port_filters(self):
        if not hasattr(self, "port_table"):
            return
        query = self.port_filter_var.get().strip().lower() if hasattr(self, "port_filter_var") else ""
        state_filter = self.port_state_var.get() if hasattr(self, "port_state_var") else "All states"

        rows = []
        for record in self.port_records:
            state = record.get("state", "")
            haystack = " ".join(str(record.get(key, "")) for key in
                                ("host", "port", "protocol", "state", "service", "reason",
                                 "product", "version", "extrainfo")).lower()
            if query and query not in haystack:
                continue
            if state_filter != "All states" and state != state_filter.lower():
                continue
            rows.append(record)

        key = self._port_sort_key
        if key == "port":
            rows.sort(key=lambda item: (item.get("port", 0), item.get("protocol", "")),
                      reverse=self._port_sort_reverse)
        elif key == "version":
            rows.sort(key=lambda item: version_label(item).lower(),
                      reverse=self._port_sort_reverse)
        else:
            rows.sort(key=lambda item: str(item.get(key, "")).lower(),
                      reverse=self._port_sort_reverse)

        for item in self.port_table.get_children():
            self.port_table.delete(item)
        for record in rows:
            state = record.get("state", "")
            if state == "open":
                tag = "open"
            elif state in ("filtered", "open|filtered", "closed|filtered", "unfiltered"):
                tag = "filtered"
            else:
                tag = "closed"
            self.port_table.insert(
                "", tk.END,
                values=(record.get("host") or "—",
                        f"{record.get('port')}/{record.get('protocol')}", state,
                        record.get("service") or "—", version_label(record),
                        record.get("reason") or "—"),
                tags=(tag,),
            )

        open_count = len(open_ports(self.port_records))
        possible_count = len(possibly_open_ports(self.port_records))
        services = len({record.get("service") for record in self.port_records
                        if record.get("state") == "open" and record.get("service")})
        possible_text = f" · {possible_count} possibly open" if possible_count else ""
        self.port_counts_var.set(
            f"{open_count} open{possible_text} · {services} service(s) · "
            f"showing {len(rows)} of {len(self.port_records)} rows"
        )
        if not rows:
            self.port_table.insert("", tk.END, values=("—", "—", "no matches", "—", "—", "adjust the filter"))

    def copy_selected_port(self):
        """Copy the selected row (or the whole result set) to the clipboard."""
        selection = self.port_table.selection()
        if selection:
            values = self.port_table.item(selection[0], "values")
            text = "  ".join(str(value) for value in values)
        else:
            lines = []
            for record in self.port_records:
                if record.get("state") == "open":
                    lines.append(f"{record.get('host')} {record.get('port')}/{record.get('protocol')} "
                                 f"{record.get('service')} {version_label(record)}".strip())
            text = "\n".join(lines)
        if not text:
            self.set_status("NOTHING TO COPY", self.MUTED)
            return
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        self.set_status("PORT DATA COPIED", self.ACCENT)
