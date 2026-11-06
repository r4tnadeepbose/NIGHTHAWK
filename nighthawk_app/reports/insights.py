"""Derived scan insights shared by the dashboard and the HTML report."""

from collections import Counter

SERVICE_ADVICE = {
    21: "FTP is exposed. Prefer SFTP/FTPS and disable anonymous access.",
    23: "Telnet is exposed. Replace it with SSH.",
    25: "SMTP is exposed. Restrict relaying and require authentication.",
    53: "DNS is reachable. Limit recursion to trusted clients.",
    139: "NetBIOS is exposed. Block it at the network edge.",
    445: "SMB is exposed. Restrict it to trusted hosts and patch regularly.",
    1433: "MSSQL is reachable. Keep it off untrusted networks.",
    3306: "MySQL is reachable. Bind it to localhost or a private network.",
    3389: "RDP is exposed. Put it behind a VPN and require MFA.",
    5432: "PostgreSQL is reachable. Restrict it to application hosts.",
    5900: "VNC is exposed. Tunnel it or disable it.",
    6379: "Redis is reachable. Require authentication and bind privately.",
    27017: "MongoDB is reachable. Enable auth and restrict network access.",
}


POSSIBLY_OPEN_STATES = {"open|filtered", "unfiltered"}


def open_ports(records):
    """Return only records whose state is open."""
    return [record for record in records if record.get("state") == "open"]


def possibly_open_ports(records):
    """Return records Nmap could not fully classify (FIN/NULL/Xmas/UDP/ACK scans)."""
    return [record for record in records if record.get("state") in POSSIBLY_OPEN_STATES]


def all_scripts(records):
    """Flatten every NSE finding across the scan."""
    return [
        {"host": record.get("host"), "port": record.get("port"),
         "protocol": record.get("protocol"), **script}
        for record in records for script in record.get("scripts", [])
    ]


def service_mix(records, limit=8):
    """Return the most common open services as (name, count) pairs."""
    counts = Counter((record.get("service") or "unknown") for record in open_ports(records))
    return counts.most_common(limit)


def recommendations(records, limit=6):
    """Turn open ports and findings into short, actionable notes."""
    current = open_ports(records)
    possible = possibly_open_ports(records)
    ports = {record.get("port") for record in current}
    notes = [advice for port, advice in sorted(SERVICE_ADVICE.items()) if port in ports]
    if possible:
        notes.append(f"{len(possible)} port(s) reported open|filtered or unfiltered. "
                     "A firewall may be dropping probes; confirm with a TCP connect scan (-sT).")
    if all_scripts(records):
        notes.append("Review the NSE findings on the Scripts tab before closing the assessment.")
    if not current and not possible:
        notes.append("No open ports were reported. Keep the host patched and re-check later.")
    if any(record.get("product") or record.get("version") for record in current):
        notes.append("Confirm that detected product versions are current and supported.")
    if not notes:
        notes.append("Review the exposed services and confirm they are intentionally reachable.")
    return notes[:limit]


def version_label(record):
    """Join product, version, and extra info into one display string."""
    parts = (record.get("product", ""), record.get("version", ""), record.get("extrainfo", ""))
    return " ".join(part for part in parts if part).strip() or "—"
