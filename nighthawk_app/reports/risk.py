"""Risk scoring shared by the desktop gauge and the HTML report."""

from .insights import all_scripts, open_ports


def assess(records):
    """Return a single severity decision for a result set."""
    current = open_ports(records)
    scripts = all_scripts(records)
    script_text = " ".join(str(script.get("output", "")) for script in scripts).casefold()

    if any(term in script_text for term in ("critical", "exploit", "remote code execution")):
        return {"label": "CRITICAL", "severity": "critical", "css": "risk-critical",
                "detail": "Critical exploit evidence detected."}
    if any(term in script_text for term in ("vulnerable", "cve-", "high severity")):
        return {"label": "HIGH RISK", "severity": "high", "css": "risk-high",
                "detail": "High-risk vulnerability evidence detected."}
    if scripts:
        return {"label": "REVIEW", "severity": "review", "css": "risk-review",
                "detail": "Script findings require review."}
    if current:
        return {"label": "EXPOSED", "severity": "exposed", "css": "risk-exposed",
                "detail": "Open services were detected."}
    return {"label": "CLEAR", "severity": "clear", "css": "risk-clear",
            "detail": "No open services or script findings."}


SEVERITY_ROLES = {
    "critical": "CRITICAL", "high": "ERROR", "review": "ORANGE",
    "exposed": "WARN", "clear": "HEALTHY",
}
