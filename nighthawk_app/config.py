"""User preference loading and saving."""

import json

from .paths import CONFIG_FILE


class ConfigMixin:
    """Read and write the small JSON settings file next to the project."""

    DEFAULTS = {
        "theme": "dark",
        "profile": "Custom / Manual",
        "target": "127.0.0.1",
        "ports": "1-1024",
        "scan_type": "TCP Connect (-sT)",
        "timing": "Insane (T5)",
        "service": True,
        "os": False,
        "nse_default": False,
        "nse_vuln": False,
        "nse_http": False,
        "nse_ssl": False,
        "traceroute": False,
        "open_only": False,
        "skip_ping": False,
        "resolve_dns": True,
        "verbose": False,
        "reasons": True,
        "extra_flags": "--reason",
        "auto_open": True,
    }

    def load_config(self):
        """Return saved settings merged over the defaults."""
        saved = {}
        if CONFIG_FILE.exists():
            try:
                saved = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                saved = {}
        return {**self.DEFAULTS, **saved}

    def save_config(self):
        """Write preferences back to disk, ignoring failures."""
        try:
            CONFIG_FILE.write_text(json.dumps(self.config, indent=2), encoding="utf-8")
        except OSError:
            pass
