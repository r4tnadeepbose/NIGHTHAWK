"""Parse Nmap XML into plain dictionaries used by every report and view."""

import xml.etree.ElementTree as ET


def parse_nmap_xml(xml_path, host):
    """Return records, host metadata, feature flags, and scan facts."""
    root = ET.parse(xml_path).getroot()
    records = []
    port_summary = []
    features = {
        "os": False, "mac": False, "uptime": False, "distance": False,
        "service_info": False, "version": False, "scripts": False,
    }
    info = {
        "os": "Unknown", "mac": "Unknown", "vendor": "Unknown", "device": "Unknown",
        "uptime": "Unknown", "distance": "Unknown", "service_info": "Unknown",
    }

    hosts_up = 0
    for host_node in root.findall("host"):
        status = host_node.find("status")
        if status is None or status.get("state") == "up":
            hosts_up += 1
        address = host_node.find("address[@addrtype='ipv4']")
        if address is None:
            address = host_node.find("address[@addrtype='ipv6']")
        if address is None:
            address = host_node.find("address")
        hostname = host_node.find("hostnames/host[@name]")
        host_label = (hostname.get("name") if hostname is not None else None) \
            or (address.get("addr") if address is not None else None) or host

        for address_node in host_node.findall("address"):
            if address_node.get("addrtype") == "mac":
                info["mac"] = address_node.get("addr", "Unknown")
                info["vendor"] = address_node.get("vendor", "Unknown")
                features["mac"] = True

        os_node = host_node.find("os")
        if os_node is not None:
            os_match = os_node.find("osmatch")
            if os_match is not None:
                info["os"] = os_match.get("name", "Unknown")
                os_class = os_match.find("osclass")
                if os_class is not None:
                    info["device"] = os_class.get("type", "Unknown")
                features["os"] = True

        uptime_node = host_node.find("uptime")
        if uptime_node is not None:
            info["uptime"] = f"{uptime_node.get('seconds')}s"
            features["uptime"] = True

        distance_node = host_node.find("distance")
        if distance_node is not None:
            info["distance"] = f"{distance_node.get('value')} hops"
            features["distance"] = True

        hostscript = host_node.find("hostscript")
        if hostscript is not None:
            for script in hostscript.findall("script"):
                if script.get("id") == "smb-os-discovery":
                    info["service_info"] = script.get("output", "").replace("\n", " | ")
                    features["service_info"] = True

        for port_node in host_node.findall("./ports/port"):
            state = port_node.find("state")
            if state is None:
                continue
            service = port_node.find("service")
            scripts = []
            for script in port_node.findall("script"):
                scripts.append({
                    "id": script.get("id", "unknown"),
                    "output": script.get("output", ""),
                })
                features["scripts"] = True
            if service is not None and (service.get("version") or service.get("product")):
                features["version"] = True

            records.append({
                "host": host_label,
                "protocol": port_node.get("protocol", ""),
                "port": int(port_node.get("portid", 0)),
                "state": state.get("state", ""),
                "reason": state.get("reason", ""),
                "service": service.get("name", "") if service is not None else "",
                "version": service.get("version", "") if service is not None else "",
                "product": service.get("product", "") if service is not None else "",
                "extrainfo": service.get("extrainfo", "") if service is not None else "",
                "scripts": scripts,
            })
        for extra_node in host_node.findall("./ports/extraports"):
            state = extra_node.get("state", "unknown")
            count = _int_attr(extra_node, "count")
            if count:
                reason_node = extra_node.find("extrareasons")
                reason = reason_node.get("reason", "") if reason_node is not None else ""
                port_summary.append({
                    "host": host_label,
                    "state": state,
                    "count": count,
                    "reason": reason,
                })

    started = _int_attr(root, "start")
    finished_node = root.find("runstats/finished")
    finished = started
    if finished_node is not None:
        finished = _int_attr(finished_node, "time") or started
    meta = {
        "nmap_version": root.get("version", "Unknown"),
        "started": root.get("startstr", ""),
        "elapsed": max(0, finished - started) if started else 0,
        "hosts_up": hosts_up,
        "hosts_scanned": len(root.findall("host")),
        "ports_total": len(records) + sum(item["count"] for item in port_summary),
        "port_summary": port_summary,
    }
    return {"records": records, "info": info, "features": features, "meta": meta}


def _int_attr(node, name):
    try:
        return int(node.get(name, "0"))
    except (TypeError, ValueError):
        return 0
