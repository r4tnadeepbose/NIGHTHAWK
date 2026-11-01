"""Command-line entry point for NIGHTHAWK."""

import sys

from . import __version__, VERSION_LABEL

HELP_TEXT = f"""NIGHTHAWK {__version__} - Advanced Network Scanner

Usage: ./scanner.py [OPTIONS]
       python -m nighthawk_app [OPTIONS]

Options:
  -h, --help       Show this help message and exit.
  -V, --version    Show version information and exit.

Requirements:
  Python 3.9 or newer with Tkinter, and Nmap on PATH.
  Run ./requirements.txt to check or install Linux prerequisites.

Reports:
  Completed scans are written to ./reports/ as HTML, JSON, CSV, and TXT files.

Packages:
  nighthawk_app.scanning   option metadata, XML parsing, process runner
  nighthawk_app.reports    risk engine, exporters, standalone HTML report
  nighthawk_app.ui         header, sidebar, tabs, dialogs, widgets

Only scan hosts you own or have permission to test."""


def main(argv=None):
    """Handle CLI flags, then start the desktop application."""
    argv = list(sys.argv[1:] if argv is None else argv)
    if "-h" in argv or "--help" in argv:
        print(HELP_TEXT)
        return 0
    if "-V" in argv or "--version" in argv:
        print(f"NIGHTHAWK {__version__} ({VERSION_LABEL})")
        return 0

    import tkinter as tk

    from .app import NighthawkApp

    root = tk.Tk()
    NighthawkApp(root)
    root.mainloop()
    return 0
