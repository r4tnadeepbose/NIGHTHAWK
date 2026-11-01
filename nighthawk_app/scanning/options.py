"""Scan profiles, option metadata, validation, and Nmap command building."""

MAX_TARGET_LENGTH = 253
MAX_PORT_EXPRESSION_LENGTH = 256
MAX_CUSTOM_FLAGS_LENGTH = 2048
MAX_REPORT_XML_BYTES = 25 * 1024 * 1024

BLOCKED_CUSTOM_FLAGS = {
    "-il", "-ir", "--datadir", "--stylesheet", "--webxml",
    "--resume", "--append-output", "-on", "-ox", "-og", "-oa",
}

SCAN_TYPES = {
    "TCP Connect (-sT)": ("-sT", "Completes a TCP connection; works without admin."),
    "TCP SYN (-sS)": ("-sS", "Half-open TCP scan; usually requires admin."),
    "UDP Scan (-sU)": ("-sU", "Probes UDP services; slower, requires admin."),
    "FIN Scan (-sF)": ("-sF", "Sends FIN packets to bypass simple firewalls."),
    "Xmas Scan (-sX)": ("-sX", "Sends FIN, PSH, and URG flags."),
    "NULL Scan (-sN)": ("-sN", "Sends TCP packets without flags."),
    "ACK Scan (-sA)": ("-sA", "Maps firewall rules."),
    "Window Scan (-sW)": ("-sW", "TCP window scan."),
    "Maimon Scan (-sM)": ("-sM", "TCP Maimon scan."),
    "Ping Discovery (-sn)": ("-sn", "Discovers online hosts without port scanning."),
    "IP Protocol (-sO)": ("-sO", "Scans IP protocols instead of ports."),
    "--- FIREWALL / IDS BYPASS ---": (None, None),
    "Fragment Packets (-f)": ("-f", "Fragments packets to bypass simple firewalls."),
    "Custom MTU (--mtu 24)": ("--mtu 24", "Sets a specific packet size to confuse firewalls."),
    "Decoy Scan (-D RND:10)": ("-D RND:10", "Cloaks the scan with 10 random decoys."),
    "Spoof MAC (--spoof-mac 0)": ("--spoof-mac 0", "Generates a random MAC address."),
    "Bad Checksum (--badsum)": ("--badsum", "Sends bad checksums to identify firewalls."),
    "Idle Scan (-sI)": ("-sI", "Advanced blind scan using a zombie host."),
    "Source Port Spoof (-g 53)": ("-g 53", "Uses a source port such as DNS 53."),
    "--- CUSTOM ---": (None, None),
    "Custom Flags": (None, "Use your own scanner flags."),
}

TIMING_TEMPLATES = {
    "Insane (T5)": "-T5", "Aggressive (T4)": "-T4", "Normal (T3)": "-T3",
    "Polite (T2)": "-T2", "Sneaky (T1)": "-T1", "Paranoid (T0)": "-T0",
}

PROFILES = {
    "Custom / Manual": None,
    "Quick TCP (Top 100)": {"type": "TCP Connect (-sT)", "ports": "Top 100",
                            "service": True, "os": False, "timing": "Insane (T5)"},
    "Intense Scan (All)": {"type": "TCP Connect (-sT)", "ports": "All",
                           "service": True, "os": True, "timing": "Aggressive (T4)"},
    "Stealth SYN (Root)": {"type": "TCP SYN (-sS)", "ports": "1-1024",
                           "service": True, "os": False, "timing": "Sneaky (T1)"},
    "Evade Firewall": {"type": "Fragment Packets (-f)", "ports": "1-1024",
                       "service": True, "os": False, "timing": "Polite (T2)"},
    "Ping Sweep": {"type": "Ping Discovery (-sn)", "ports": "N/A",
                   "service": False, "os": False, "timing": "Normal (T3)"},
}

# Data-driven sidebar checklist: (key, label, one-line hint, default).
CHECK_GROUPS = (
    ("DETECTION", (
        ("service", "Service & version", "Fingerprint services with -sV", True),
        ("os", "OS fingerprint", "Guess the operating system with -O", False),
    )),
    ("SCRIPTS", (
        ("nse_default", "Default scripts", "Run the safe NSE default set (-sC)", False),
        ("nse_vuln", "Vulnerability scripts", "Run the NSE vuln category", False),
        ("nse_http", "HTTP enumeration", "Enumerate web paths with http-enum", False),
        ("nse_ssl", "SSL cipher audit", "List TLS ciphers with ssl-enum-ciphers", False),
    )),
    ("DISCOVERY & OUTPUT", (
        ("traceroute", "Traceroute", "Map the path with --traceroute", False),
        ("open_only", "Open ports only", "Hide closed ports with --open", False),
        ("skip_ping", "Skip host discovery", "Treat the host as up with -Pn", False),
        ("resolve_dns", "Resolve DNS names", "Turn off to use -n", True),
        ("verbose", "Verbose output", "Stream extra detail with -v", False),
        ("reasons", "Show port reasons", "Annotate states with --reason", True),
    )),
)

CHECK_LABELS = {key: label for _, entries in CHECK_GROUPS for key, label, _, _ in entries}
CHECK_DEFAULTS = {key: default for _, entries in CHECK_GROUPS for key, _, _, default in entries}

EVASION_TYPES = {
    "Fragment Packets (-f)", "Custom MTU (--mtu 24)", "Decoy Scan (-D RND:10)",
    "Spoof MAC (--spoof-mac 0)", "Bad Checksum (--badsum)", "Idle Scan (-sI)",
    "Source Port Spoof (-g 53)",
}
NON_STANDARD_TYPES = {"Ping Discovery (-sn)", "IP Protocol (-sO)"}


def valid_ports(expression):
    """Accept only simple bounded port lists, ranges, or --top-ports forms."""
    if not expression:
        return False
    if expression.startswith("--top-ports"):
        parts = expression.split()
        return len(parts) == 2 and parts[1].isdigit() and 0 < int(parts[1]) <= 65535
    if len(expression) > MAX_PORT_EXPRESSION_LENGTH:
        return False
    for part in expression.split(","):
        part = part.strip()
        if not part:
            return False
        if "-" in part:
            low, _, high = part.partition("-")
            if not (low.isdigit() and high.isdigit()):
                return False
            if not (0 < int(low) <= int(high) <= 65535):
                return False
        elif not (part.isdigit() and 0 < int(part) <= 65535):
            return False
    return True


def parse_flags(text):
    """Split a flag string into tokens, rejecting paths and output overrides."""
    tokens = []
    for token in (text or "").split():
        lowered = token.lower()
        if lowered in BLOCKED_CUSTOM_FLAGS or lowered.startswith(("--script=", "-ox", "-oa", "-og", "-on")):
            raise ValueError(f"flag '{token}' is blocked for safety")
        tokens.append(token)
    return tokens


def apply_port_preset_text(preset):
    """Translate a friendly preset label into an Nmap port expression."""
    return {
        "Top 100": "--top-ports 100",
        "Top 1000": "--top-ports 1000",
        "All": "1-65535",
    }.get(preset, "1-1024")


def build_command(engine, *, scan_type, timing, ports, flags_text, check_state,
                  custom_flags=False, xml_path, target):
    """Build a validated Nmap argument list from the current form state."""
    if len(target) > MAX_TARGET_LENGTH:
        raise ValueError("target is too long")
    if len(flags_text) > MAX_CUSTOM_FLAGS_LENGTH:
        raise ValueError("custom flags are too long")

    extra = parse_flags(flags_text)
    command = [engine]

    if custom_flags:
        if not extra:
            raise ValueError("enter custom scanner flags")
        command.extend(extra)
    else:
        base_flag = SCAN_TYPES[scan_type][0]
        if base_flag:
            command.append(base_flag)
        command.append(TIMING_TEMPLATES[timing])

        standard = scan_type not in NON_STANDARD_TYPES and scan_type not in EVASION_TYPES
        if check_state.get("service") and standard:
            command.append("-sV")
        if check_state.get("os") and standard:
            command.append("-O")
        if check_state.get("nse_default"):
            command.append("-sC")
        if check_state.get("nse_vuln"):
            command.extend(["--script", "vuln"])
        if check_state.get("nse_http"):
            command.extend(["--script", "http-enum"])
        if check_state.get("nse_ssl"):
            command.extend(["--script", "ssl-enum-ciphers"])
        if check_state.get("traceroute") and standard:
            command.append("--traceroute")
        if check_state.get("open_only"):
            command.append("--open")
        if check_state.get("skip_ping"):
            command.append("-Pn")
        if not check_state.get("resolve_dns", True):
            command.append("-n")
        if check_state.get("verbose"):
            command.append("-v")
        if check_state.get("reasons") and "--reason" not in extra:
            command.append("--reason")
        command.extend(extra)

    if ports != "N/A":
        if ports.startswith("--top-ports"):
            command.extend(ports.split())
        else:
            command.extend(["-p", ports])

    command.extend(["-oX", str(xml_path), target])
    return command
