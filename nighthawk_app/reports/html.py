"""Standalone HTML report renderer."""

import html
import json

from .insights import all_scripts, open_ports, recommendations, service_mix, version_label
from .risk import assess
from .. import __version__, VERSION_LABEL
from ..paths import report_logo_href


def render_report(data, base, palettes, version=__version__):
    """Return a complete standalone HTML document for one scan."""
    records = data.get("results", [])
    port_summary = data.get("port_summary", [])
    info = data.get("info", {})
    current = open_ports(records)
    scripts = all_scripts(records)
    assessment = assess(records)
    saved_at = html.escape(str(data.get("created", "")).replace("T", " ")[:19] or "—")

    rows = []
    for record in records:
        state = html.escape(str(record.get("state", "")))
        state_class = "state-open" if state == "open" else "state-other"
        rows.append(
            "<tr><td>{}</td><td class='mono'>{}</td><td class='{}'>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>".format(
                html.escape(str(record.get("host", "") or "—")),
                html.escape(f"{record.get('port', '')}/{record.get('protocol', '')}"),
                state_class, state,
                html.escape(str(record.get("service", "") or "—")),
                html.escape(version_label(record)),
                html.escape(str(record.get("reason", "") or "—")),
            )
        )
    if not rows:
        rows.append("<tr><td colspan='6' class='empty'>No individual port results were returned.</td></tr>")
    summary_rows = "".join(
        "<tr><td>{}</td><td class='mono'>{} ports</td><td class='state-other'>{}</td>"
        "<td colspan='2'>Grouped by Nmap</td><td>{}</td></tr>".format(
            html.escape(str(item.get("host", "—"))),
            item.get("count", 0),
            html.escape(str(item.get("state", "unknown"))),
            html.escape(str(item.get("reason", "") or "—")),
        )
        for item in port_summary
    )

    script_blocks = []
    for entry in scripts:
        script_blocks.append(
            "<article class='script'><header>{}</header><pre>{}</pre></article>".format(
                html.escape(f"{entry.get('host') or ''} {entry['port']}/{entry['protocol']}  •  {entry['id']}"),
                html.escape(str(entry.get("output", ""))),
            )
        )

    metadata = (
        ("Target", data.get("target", "Unknown")),
        ("Port range", data.get("ports", "Unknown")),
        ("MAC address", info.get("mac", "Unknown")),
        ("Operating system", info.get("os", "Unknown")),
        ("Network distance", info.get("distance", "Unknown")),
        ("Nmap version", data.get("nmap_version", "Unknown")),
        ("Scan started", data.get("started", "Unknown")),
        ("Duration", data.get("duration", "Unknown")),
    )
    meta_html = "".join(
        "<div class='meta'><span>{}</span><strong>{}</strong></div>".format(
            html.escape(label), html.escape(str(value))
        ) for label, value in metadata
    )

    mix = service_mix(records)
    chips = "".join(
        "<span class='chip'>{}<b>{}</b></span>".format(html.escape(name), count)
        for name, count in mix
    ) or "<span class='empty-inline'>No services reported.</span>"
    notes = recommendations(records)
    notes_html = "".join(f"<li>{html.escape(note)}</li>" for note in notes)
    option_chips = "".join(
        f"<span class='chip mono'>{html.escape(option)}</span>" for option in data.get("options", [])
    ) or "<span class='empty-inline'>Base scan only</span>"
    command = html.escape(str(data.get("command", "—")))

    dark, light = palettes["dark"], palettes["light"]
    css = f"""
:root {{ color-scheme:dark;
  --bg:{dark['BG']}; --panel:{dark['PANEL']}; --panel-2:{dark['PANEL2']}; --panel-3:{dark['PANEL3']};
  --line:{dark['BORDER']}; --line-soft:{dark['BORDER2']}; --text:{dark['FG']}; --muted:{dark['MUTED']};
  --accent:{dark['ACCENT']}; --accent-hover:{dark['ACCENT_HOVER']}; --on-accent:{dark['ON_ACCENT']};
  --warn:{dark['WARN']}; --error:{dark['ERROR']}; --healthy:{dark['HEALTHY']}; --orange:{dark['ORANGE']}; --critical:{dark['CRITICAL']}; }}
html[data-theme="light"] {{ color-scheme:light;
  --bg:{light['BG']}; --panel:{light['PANEL']}; --panel-2:{light['PANEL2']}; --panel-3:{light['PANEL3']};
  --line:{light['BORDER']}; --line-soft:{light['BORDER2']}; --text:{light['FG']}; --muted:{light['MUTED']};
  --accent:{light['ACCENT']}; --accent-hover:{light['ACCENT_HOVER']}; --on-accent:{light['ON_ACCENT']};
  --warn:{light['WARN']}; --error:{light['ERROR']}; --healthy:{light['HEALTHY']}; --orange:{light['ORANGE']}; --critical:{light['CRITICAL']}; }}
* {{ box-sizing:border-box; }}
body {{ margin:0; background:var(--bg); color:var(--text); font:14px/1.55 "Segoe UI",system-ui,sans-serif; }}
.topbar {{ display:flex; align-items:center; gap:14px; padding:14px max(24px,calc((100vw - 1480px)/2)); background:var(--panel); border-bottom:1px solid var(--line); }}
.mark {{ display:grid; place-items:center; }} .mark img {{ width:38px; height:38px; object-fit:contain; }}
.brand {{ color:var(--accent); font:700 15px/1 "Consolas",ui-monospace,monospace; letter-spacing:.14em; }}
.brand small {{ display:block; margin-top:5px; color:var(--muted); font:600 9px/1 "Consolas",ui-monospace,monospace; letter-spacing:.16em; }}
.status {{ margin-left:auto; padding:5px 9px; border:1px solid var(--line); color:var(--accent); font:700 10px "Consolas",ui-monospace,monospace; letter-spacing:.12em; }}
.theme-toggle {{ border:1px solid var(--line); background:transparent; color:var(--muted); padding:7px 11px; font:700 10px "Consolas",ui-monospace,monospace; letter-spacing:.1em; cursor:pointer; }}
.theme-toggle:hover, .theme-toggle:focus-visible {{ border-color:var(--accent); color:var(--accent); outline:none; }}
main {{ max-width:1480px; margin:0 auto; padding:30px 24px 44px; }}
h1 {{ margin:0; font:700 24px/1.2 "Consolas",ui-monospace,monospace; letter-spacing:.02em; }}
.sub {{ margin:8px 0 24px; color:var(--muted); font-size:13px; }} .sub strong {{ color:var(--text); font-weight:600; }}
.summary {{ display:grid; grid-template-columns:repeat(5,minmax(0,1fr)); gap:10px; margin-bottom:14px; }}
.card, .panel {{ background:var(--panel); border:1px solid var(--line); }}
.card {{ padding:13px 15px; }}
.card span {{ display:block; color:var(--muted); font:700 10px "Consolas",ui-monospace,monospace; letter-spacing:.12em; text-transform:uppercase; }}
.card strong {{ display:block; margin-top:7px; color:var(--text); font:700 22px "Consolas",ui-monospace,monospace; overflow-wrap:anywhere; }}
.card.good strong {{ color:var(--healthy); }} .card.warn strong {{ color:var(--warn); }} .card.bad strong {{ color:var(--error); }}
.grid {{ display:grid; grid-template-columns:1.05fr 1fr; gap:14px; margin-bottom:14px; }}
.panel-title {{ margin:0; padding:12px 15px; border-bottom:1px solid var(--line); color:var(--muted); font:700 11px "Consolas",ui-monospace,monospace; letter-spacing:.14em; text-transform:uppercase; }}
.metadata {{ padding:4px 15px; }}
.meta {{ display:grid; grid-template-columns:150px 1fr; gap:12px; padding:10px 0; border-bottom:1px solid var(--line-soft); font-size:13px; }}
.meta:last-child {{ border-bottom:0; }} .meta span {{ color:var(--muted); }} .meta strong {{ font-weight:600; overflow-wrap:anywhere; }}
.risk {{ display:flex; align-items:center; gap:20px; padding:20px 16px; }}
.risk-badge {{ flex:0 0 auto; min-width:112px; padding:16px 12px; border:2px solid currentColor; text-align:center; font:700 12px "Consolas",ui-monospace,monospace; letter-spacing:.1em; }}
.risk-badge small {{ display:block; margin-top:6px; color:var(--muted); font:400 9px "Consolas",ui-monospace,monospace; letter-spacing:.08em; }}
.risk p {{ margin:0; color:var(--muted); font-size:13px; }} .risk-counts {{ display:block; margin-top:8px; color:var(--text); }}
.risk-critical {{ color:var(--critical); }} .risk-high {{ color:var(--error); }} .risk-review {{ color:var(--orange); }} .risk-exposed {{ color:var(--warn); }} .risk-clear {{ color:var(--healthy); }}
.chips {{ display:flex; flex-wrap:wrap; gap:8px; padding:16px; }}
.chip {{ display:inline-flex; gap:8px; align-items:center; border:1px solid var(--line); background:var(--panel-2); padding:6px 9px; color:var(--text); font-size:12px; }}
.chip b {{ color:var(--accent); font:700 11px "Consolas",ui-monospace,monospace; }}
.recs {{ margin:0; padding:14px 16px 16px 34px; color:var(--text); font-size:13px; }} .recs li {{ margin:7px 0; color:var(--muted); }} .recs li::marker {{ color:var(--accent); }}
.command-panel {{ margin-bottom:14px; }} .command-body {{ padding:14px 15px; }} .command-body code {{ display:block; padding:11px 12px; background:var(--panel-2); border:1px solid var(--line-soft); color:var(--accent); font:12px/1.5 "Consolas",ui-monospace,monospace; overflow-wrap:anywhere; }}
.config-chips {{ display:flex; flex-wrap:wrap; gap:8px; margin-top:11px; }}
.empty-inline {{ color:var(--muted); font-size:13px; }}
.toolbar {{ display:flex; align-items:center; gap:8px; padding:12px 15px; border-bottom:1px solid var(--line); flex-wrap:wrap; }}
button.action {{ border:1px solid var(--line); background:transparent; color:var(--text); padding:8px 12px; font:700 10px "Consolas",ui-monospace,monospace; letter-spacing:.08em; cursor:pointer; }}
button.action:hover, button.action:focus-visible {{ border-color:var(--accent); color:var(--accent); outline:none; }}
input#filter {{ margin-left:auto; min-width:260px; background:var(--panel-2); color:var(--text); border:1px solid var(--line); padding:8px 10px; font:13px "Segoe UI",system-ui,sans-serif; }}
input#filter::placeholder {{ color:var(--muted); }} input#filter:focus {{ outline:none; border-color:var(--accent); }}
.table-wrap {{ overflow-x:auto; }} table {{ width:100%; border-collapse:collapse; }}
th, td {{ padding:11px 15px; text-align:left; border-bottom:1px solid var(--line-soft); font-size:13px; }}
th {{ background:var(--panel-3); color:var(--muted); font:700 10px "Consolas",ui-monospace,monospace; letter-spacing:.12em; text-transform:uppercase; }}
tbody tr:hover td {{ background:var(--panel-2); }}
.mono, .state-open {{ font-family:"Consolas",ui-monospace,monospace; }}
.state-open {{ color:var(--healthy); font-weight:700; }} .state-other {{ color:var(--warn); }}
.scripts {{ margin-top:14px; }} .script {{ margin:14px 15px; border:1px solid var(--line); background:var(--panel-2); }}
.script header {{ padding:9px 11px; border-bottom:1px solid var(--line); color:var(--accent); font:700 10px "Consolas",ui-monospace,monospace; letter-spacing:.06em; }}
pre {{ margin:0; padding:13px; overflow:auto; white-space:pre-wrap; color:var(--text); font:12px/1.5 "Consolas",ui-monospace,monospace; }}
.empty {{ margin:0; padding:20px 15px; color:var(--muted); text-align:center; font-size:13px; }}
footer {{ max-width:1480px; margin:0 auto; padding:0 24px 28px; color:var(--muted); font:10px "Consolas",ui-monospace,monospace; letter-spacing:.1em; text-transform:uppercase; }}
@media (max-width:1100px) {{ .summary {{ grid-template-columns:repeat(3,minmax(0,1fr)); }} }}
@media (max-width:900px) {{ main {{ padding:20px 14px 32px; }} .summary {{ grid-template-columns:1fr 1fr; }} .grid {{ display:block; }} .grid > .panel {{ margin-bottom:14px; }} .meta {{ grid-template-columns:120px 1fr; }} input#filter {{ width:100%; margin-left:0; min-width:0; }} footer {{ padding:0 14px 22px; }} }}
"""

    head_js = (
        "<script>try{document.documentElement.dataset.theme="
        "localStorage.getItem('nighthawk-theme')||'dark';}"
        "catch(e){document.documentElement.dataset.theme='dark';}</script>"
    )

    report_js = (
        "<script>\nconst reportData = {json:" + json.dumps(data).replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")
        + ",csv:" + json.dumps(base.with_suffix(".csv").read_text(encoding="utf-8"))
        + ",txt:" + json.dumps(base.with_suffix(".txt").read_text(encoding="utf-8"))
        + "};\n"
        "function downloadFile(ext){const blob=new Blob([typeof reportData[ext]==='string'?reportData[ext]:JSON.stringify(reportData[ext],null,2)],{type:'text/plain'});const url=URL.createObjectURL(blob);const link=document.createElement('a');link.href=url;link.download='" + base.name + ".'+ext;link.click();URL.revokeObjectURL(url);}\n"
        "const themeButton=document.getElementById('theme-toggle');\n"
        "function syncThemeButton(){const light=document.documentElement.dataset.theme==='light';themeButton.textContent=light?'Dark':'Light';themeButton.setAttribute('aria-pressed',String(light));}\n"
        "themeButton.addEventListener('click',()=>{const next=document.documentElement.dataset.theme==='light'?'dark':'light';document.documentElement.dataset.theme=next;try{localStorage.setItem('nighthawk-theme',next);}catch(error){}syncThemeButton();});\n"
        "syncThemeButton();\n"
        "document.getElementById('filter').addEventListener('input',function(){const query=this.value.toLowerCase();document.querySelectorAll('#results tbody tr').forEach(function(row){row.hidden=!row.textContent.toLowerCase().includes(query);});});\n"
        "</script>"
    )

    logo_href = html.escape(report_logo_href())
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>NIGHTHAWK {version} — Scan report</title>
{head_js}
<style>{css}</style>
</head>
<body>
<header class="topbar">
  <div class="mark"><img src="{logo_href}" alt="Nighthawk"></div>
  <div class="brand">NIGHTHAWK<small>ADVANCED NETWORK SCANNER · {VERSION_LABEL} · {version}</small></div>
  <span class="status">SCAN COMPLETE</span>
  <button class="theme-toggle" id="theme-toggle" type="button" aria-label="Toggle color theme">Light</button>
</header>
<main>
  <div class="page-head">
    <h1>Scan report</h1>
    <p class="sub"><strong>{html.escape(str(data.get('target', 'Unknown')))}</strong> &nbsp;/&nbsp; ports {html.escape(str(data.get('ports', '')))} &nbsp;/&nbsp; {saved_at}</p>
  </div>

  <section class="summary" aria-label="Scan summary">
    <div class="card good"><span>Hosts up</span><strong>{data.get('hosts_up', 1)}</strong></div>
    <div class="card"><span>Hosts scanned</span><strong>{data.get('hosts_scanned', data.get('hosts_up', 1))}</strong></div>
    <div class="card"><span>Open ports</span><strong>{data.get('open_ports', len(current))}</strong></div>
    <div class="card {'bad' if assessment['severity'] in ('critical', 'high') else ''}"><span>Script findings</span><strong>{data.get('script_findings', len(scripts))}</strong></div>
    <div class="card"><span>Total port records</span><strong>{data.get('ports_total', len(records))}</strong></div>
  </section>

  <section class="grid">
    <div class="panel"><h2 class="panel-title">Target information</h2><div class="metadata">{meta_html}</div></div>
    <div class="panel">
      <h2 class="panel-title">Risk assessment</h2>
      <div class="risk {assessment['css']}">
        <div class="risk-badge">{assessment['label']}<small>assessment</small></div>
        <p>{assessment['detail']}<span class="risk-counts">{len(current)} open port(s) · {len(scripts)} script finding(s)</span></p>
      </div>
    </div>
  </section>

  <section class="grid">
    <div class="panel"><h2 class="panel-title">Service mix</h2><div class="chips">{chips}</div></div>
    <div class="panel"><h2 class="panel-title">Recommendations</h2><ul class="recs">{notes_html}</ul></div>
  </section>

  <section class="panel command-panel">
    <h2 class="panel-title">Scan configuration</h2>
    <div class="command-body"><code>{command}</code><div class="config-chips">{option_chips}</div></div>
  </section>

  <section class="panel">
    <h2 class="panel-title">Ports &amp; services</h2>
    <div class="toolbar">
      <button class="action" type="button" onclick="downloadFile('json')">Export JSON</button>
      <button class="action" type="button" onclick="downloadFile('csv')">Export CSV</button>
      <button class="action" type="button" onclick="downloadFile('txt')">Export TXT</button>
      <input id="filter" type="search" placeholder="Filter port, state, service, or version">
    </div>
    <div class="table-wrap">
      <table id="results">
        <thead><tr><th>Host</th><th>Port</th><th>State</th><th>Service</th><th>Version</th><th>Reason</th></tr></thead>
        <tbody>{''.join(rows)}{summary_rows}</tbody>
      </table>
    </div>
  </section>

  <section class="panel scripts">
    <h2 class="panel-title">Script output</h2>
    {''.join(script_blocks) or "<p class='empty'>No Nmap script output was returned for this scan.</p>"}
  </section>
</main>
<footer>NIGHTHAWK {version} · {VERSION_LABEL} · local report · {saved_at}</footer>
{report_js}
</body>
</html>"""
