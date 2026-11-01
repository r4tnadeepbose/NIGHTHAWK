#!/usr/bin/env python3
"""NIGHTHAWK launcher.

The application lives in the ``nighthawk_app`` package. This file stays tiny so
``./scanner.py``, the Makefile, and the installed launcher keep working.
"""

from nighthawk_app.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
