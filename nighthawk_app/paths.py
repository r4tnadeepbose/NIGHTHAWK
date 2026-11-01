"""Filesystem locations used by NIGHTHAWK.

Keeping every path in one module means the scanner runs the same whether it is
started through ``scanner.py``, ``python -m nighthawk_app``, or an installed
launcher.
"""

from pathlib import Path

PACKAGE_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = PACKAGE_DIR.parent
CONFIG_FILE = PROJECT_ROOT / "nighthawk_config.json"
REPORTS_DIR = PROJECT_ROOT / "reports"
ASSETS_DIR = PACKAGE_DIR / "assets"

README_FILE = PROJECT_ROOT / "README.md"
HELP_FILE = PROJECT_ROOT / "HELP.md"


def logo_path():
    """Return the muted report logo, falling back to the original mark."""
    muted = ASSETS_DIR / "logo_muted.png"
    return muted if muted.exists() else ASSETS_DIR / "logo.png"


def report_logo_href():
    """Relative path from a report in ``reports/`` to the logo asset."""
    try:
        relative = logo_path().relative_to(PROJECT_ROOT)
    except ValueError:
        return "../nighthawk_app/assets/logo_muted.png"
    return "../" + relative.as_posix()
