"""Unit tests for the non-GUI core."""

import tempfile
import unittest
from pathlib import Path

from nighthawk_app import __version__
from nighthawk_app.reports.html import render_report
from nighthawk_app.reports.insights import possibly_open_ports, recommendations, service_mix
from nighthawk_app.reports.risk import assess
from nighthawk_app.scanning.options import (
    build_command, is_cidr_target, parse_flags, split_targets, valid_ports,
)
from nighthawk_app.scanning.parser import parse_nmap_xml
from nighthawk_app.theme import PALETTES


def record(port, state="open", service="http", **extra):
    base = {"port": port, "protocol": "tcp", "state": state, "reason": "syn-ack",
            "service": service, "product": "", "version": "", "extrainfo": "", "scripts": []}
    base.update(extra)
    return base


class ValidationTests(unittest.TestCase):
    def test_ports(self):
        self.assertTrue(valid_ports("22,80,443"))
        self.assertTrue(valid_ports("1-1024"))
        self.assertTrue(valid_ports("--top-ports 1000"))
        self.assertFalse(valid_ports("0-10"))
        self.assertFalse(valid_ports("1-70000"))
        self.assertFalse(valid_ports("80,abc"))

    def test_cidr_target(self):
        self.assertTrue(is_cidr_target("192.168.1.0/24"))
        self.assertTrue(is_cidr_target("2001:db8::/64"))
        self.assertFalse(is_cidr_target("192.168.1.0/33"))
        self.assertFalse(is_cidr_target("host/name"))
        self.assertFalse(is_cidr_target("192.168.1.0/24,192.168.2.0/24"))

    def test_flags_blocked(self):
        with self.assertRaises(ValueError):
            parse_flags("-sV -oX report.xml")
        self.assertEqual(parse_flags("-sV --reason"), ["-sV", "--reason"])


class CommandTests(unittest.TestCase):
    def test_command_contains_options(self):
        state = {key: False for key in ("service", "os", "nse_default", "nse_vuln",
                                        "nse_http", "nse_ssl", "traceroute", "open_only",
                                        "skip_ping", "verbose", "reasons", "resolve_dns")}
        state.update({"service": True, "traceroute": True, "open_only": True, "reasons": True})
        command = build_command(
            "nmap", scan_type="TCP Connect (-sT)", timing="Insane (T5)",
            ports="1-1024", flags_text="", check_state=state,
            xml_path="out.xml", target="127.0.0.1",
        )
        self.assertEqual(command[0], "nmap")
        for flag in ("-sT", "-T5", "-sV", "--traceroute", "--reason"):
            self.assertIn(flag, command)
        self.assertNotIn("--open", command)
        self.assertIn("-oX", command)

    def test_multi_target_split(self):
        self.assertEqual(split_targets("192.168.1.1,192.168.1.5"),
                         ["192.168.1.1", "192.168.1.5"])
        self.assertEqual(split_targets(" 10.0.0.1, 10.0.0.2 "), ["10.0.0.1", "10.0.0.2"])
        command = build_command(
            "nmap", scan_type="TCP Connect (-sT)", timing="Normal (T3)",
            ports="80", flags_text="", check_state={},
            xml_path="out.xml", target="192.168.1.1,192.168.1.5",
        )
        self.assertEqual(command[-2:], ["192.168.1.1", "192.168.1.5"])

    def test_empty_target_rejected(self):
        with self.assertRaises(ValueError):
            build_command("nmap", scan_type="TCP Connect (-sT)", timing="Normal (T3)",
                          ports="80", flags_text="", check_state={},
                          xml_path="out.xml", target=" , ")


class RiskTests(unittest.TestCase):
    def test_severity(self):
        self.assertEqual(assess([])["severity"], "clear")
        self.assertEqual(assess([record(80)])["severity"], "exposed")
        self.assertEqual(assess([record(80, scripts=[{"id": "x", "output": "note"}])])["severity"], "review")
        self.assertEqual(assess([record(80, scripts=[{"id": "x", "output": "CVE-2024-1"}])])["severity"], "high")
        self.assertEqual(assess([record(80, scripts=[{"id": "x", "output": "remote code execution"}])])["severity"], "critical")

    def test_possibly_open_states(self):
        records = [record(80, state="open|filtered"), record(53, state="unfiltered")]
        self.assertEqual(len(possibly_open_ports(records)), 2)
        assessment = assess(records)
        self.assertEqual(assessment["severity"], "exposed")
        self.assertIn("open|filtered", assessment["detail"])
        notes = recommendations(records)
        self.assertTrue(any("open|filtered" in note for note in notes))
        self.assertEqual(assess([record(80, state="closed")])["severity"], "clear")

    def test_insights(self):
        records = [record(445, service="microsoft-ds"), record(445, service="microsoft-ds")]
        self.assertEqual(service_mix(records)[0], ("microsoft-ds", 2))
        notes = recommendations(records)
        self.assertTrue(any("SMB" in note for note in notes))


class ParserTests(unittest.TestCase):
    XML = """<?xml version="1.0"?>
<nmaprun version="7.99" start="100" startstr="now">
  <host><status state="up"/><address addr="192.0.2.1" addrtype="ipv4"/>
    <hostnames><host name="alpha.example" type="PTR"/></hostnames>
    <ports><port protocol="tcp" portid="80"><state state="open" reason="syn-ack"/>
      <service name="http"/></port></ports></host>
  <host><status state="up"/><address addr="192.0.2.2" addrtype="ipv4"/>
    <ports><port protocol="tcp" portid="53"><state state="open|filtered" reason="no-response"/>
      <service name="domain"/></port></ports></host>
  <host><status state="down"/><address addr="192.0.2.3" addrtype="ipv4"/></host>
  <host><status state="up"/><address addr="192.0.2.4" addrtype="ipv4"/>
    <ports><extraports state="filtered" count="1000"><extrareasons reason="no-response" count="1000"/></extraports></ports>
  </host>
  <runstats><finished time="110"/></runstats>
</nmaprun>"""

    def test_multi_host_parse(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "scan.xml"
            path.write_text(self.XML, encoding="utf-8")
            parsed = parse_nmap_xml(path, "192.0.2.1,192.0.2.2")
        self.assertEqual(parsed["meta"]["hosts_up"], 3)
        self.assertEqual(parsed["meta"]["elapsed"], 10)
        hosts = {record["host"] for record in parsed["records"]}
        self.assertEqual(hosts, {"alpha.example", "192.0.2.2"})
        states = {record["state"] for record in parsed["records"]}
        self.assertIn("open|filtered", states)
        self.assertEqual(parsed["meta"]["hosts_scanned"], 4)
        self.assertEqual(parsed["meta"]["ports_total"], 1002)
        self.assertEqual(parsed["meta"]["port_summary"][0]["count"], 1000)


class ReportTests(unittest.TestCase):
    def test_report_renders_v3(self):
        data = {
            "target": "192.0.2.10", "ports": "1-1024",
            "info": {"mac": "aa:bb", "os": "Linux", "distance": "1 hops"},
            "created": "2026-11-01T12:00:00", "results": [record(80, product="nginx", version="1.24")],
            "nmap_version": "7.99", "started": "now", "duration": "0:00:10",
            "command": "NIGHTHAWK -sT -p 80 192.0.2.10", "options": ["-sT", "-sV"],
        }
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder) / "nighthawk_test"
            base.with_suffix(".csv").write_text("a,b\n", encoding="utf-8")
            base.with_suffix(".txt").write_text("row\n", encoding="utf-8")
            page = render_report(data, base, PALETTES)
        self.assertIn(__version__, page)
        self.assertIn("Service mix", page)
        self.assertIn("Recommendations", page)
        self.assertIn("Scan configuration", page)
        self.assertIn("theme-toggle", page)
        self.assertIn("192.0.2.10", page)

    def test_report_escapes_embedded_scan_data(self):
        data = {
            "target": "127.0.0.1", "ports": "80",
            "info": {}, "results": [record(
                80, scripts=[{"id": "test", "output": "</script><script>broken()</script>"}],
            )],
            "created": "2026-11-01T12:00:00", "nmap_version": "7.99",
            "started": "now", "duration": "0:00:01", "options": [],
        }
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder) / "nighthawk_test"
            base.with_suffix(".csv").write_text("a,b\n", encoding="utf-8")
            base.with_suffix(".txt").write_text("row\n", encoding="utf-8")
            page = render_report(data, base, PALETTES)
        self.assertNotIn("</script><script>broken()</script>", page)
        self.assertIn("\\u003c/script\\u003e", page)
        self.assertIn("Total port records", page)


if __name__ == "__main__":
    unittest.main()
