"""JSON, CSV, and TXT report writers."""

import csv
import json

from .insights import version_label
from ..paths import REPORTS_DIR


def ensure_reports_dir():
    """Create the reports folder if it does not exist."""
    REPORTS_DIR.mkdir(exist_ok=True)
    return REPORTS_DIR


def safe_csv_value(value):
    """Prefix spreadsheet formula-like cells so CSV files stay inert."""
    text = str(value)
    if text.startswith(("=", "+", "-", "@")):
        return "'" + text
    return text


def write_reports(base, data, features):
    """Write JSON, CSV, and TXT companions for one scan and return the TXT body."""
    records = data["results"]

    base.with_suffix(".json").write_text(json.dumps(data, indent=2), encoding="utf-8")

    csv_fields = ["host", "protocol", "port", "state", "reason", "service"]
    if features["version"]:
        csv_fields.extend(["version", "product", "extrainfo"])
    with base.with_suffix(".csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=csv_fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(
            {key: safe_csv_value(value) for key, value in row.items() if key in csv_fields}
            for row in records
        )

    txt_content = "\n".join(
        f"{row['host']}:{row['port']}/{row['protocol']} {row['state']} "
        f"{row['reason']} {row['service']} {version_label(row) if features['version'] else ''}".strip()
        for row in records
    )
    base.with_suffix(".txt").write_text(txt_content, encoding="utf-8")
    return txt_content
