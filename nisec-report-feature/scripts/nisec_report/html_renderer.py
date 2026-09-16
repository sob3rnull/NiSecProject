"""
html_renderer.py — the ONLY file that produces HTML. Gemini never generates
markup; it only ever supplies plain text/JSON, which is escaped here like
any other untrusted input (spec item 18).

Single self-contained file: no CDN, no JS, no external CSS. Charts are
inline SVG built from numbers already computed by evidence_parser.py.
"""
from __future__ import annotations
from html import escape as esc


def _svg_hbar(pairs: list[tuple[str, float]], color: str, unit: str = "") -> str:
    """pairs: list of (label, value). Same layout logic as the earlier
    bash chart generator, ported to Python with proper HTML escaping."""
    if not pairs:
        return "<p class='muted'>No data available for this chart.</p>"
    max_v = max(v for _, v in pairs) or 1
    label_w, chart_w, bar_h, gap, right_margin = 210, 350, 26, 12, 90
    svg_w = label_w + chart_w + right_margin
    total_h = len(pairs) * (bar_h + gap) + gap
    parts = [f'<svg viewBox="0 0 {svg_w} {total_h}" class="chart" role="img">']
    y = gap
    for label, value in pairs:
        bw = max(2, (value / max_v) * chart_w)
        parts.append(
            f'<text x="{label_w - 10}" y="{y + bar_h // 2}" class="barlabel" '
            f'text-anchor="end" dominant-baseline="middle">{esc(str(label))}</text>'
        )
        parts.append(f'<rect x="{label_w}" y="{y}" width="{bw:.1f}" height="{bar_h}" rx="4" fill="{color}"/>')
        parts.append(
            f'<text x="{label_w + bw + 8:.1f}" y="{y + bar_h // 2}" class="barvalue" '
            f'dominant-baseline="middle">{esc(str(value))}{esc(unit)}</text>'
        )
        y += bar_h + gap
    parts.append("</svg>")
    return "".join(parts)


def _table(headers: list[str], rows: list[list[str]]) -> str:
    if not rows:
        return "<p class='muted'>No data available.</p>"
    head = "".join(f"<th>{esc(h)}</th>" for h in headers)
    body = "".join(
        "<tr>" + "".join(f"<td>{esc(str(c))}</td>" for c in row) + "</tr>"
        for row in rows
    )
    return f"<table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>"


def _severity_pill(sev: str) -> str:
    cls = {"HIGH": "pill-high", "MEDIUM": "pill-med"}.get(sev, "pill-low")
    return f'<span class="pill {cls}">{esc(sev)}</span>'


def _ai_block(text: str, ai_status: str) -> str:
    """Every AI-authored paragraph is escaped exactly like evidence text —
    Gemini output is untrusted input, not markup (spec item 18)."""
    note = "" if ai_status == "ok" else '<div class="ai-note">⚠ AI analysis unavailable — showing fallback text.</div>'
    return f'{note}<p class="ai-text">{esc(text)}</p>'


def render_html(report_data, narrative: dict, ai_status: str, ai_meta: dict) -> str:
    d = report_data
    inc = d.incident
    stats = d.statistics

    css = """
    :root { color-scheme: dark; }
    body { background:#14161b; color:#e6e8eb; font-family:-apple-system,Segoe UI,Roboto,Arial,sans-serif; margin:0; }
    .wrap { max-width:980px; margin:0 auto; padding:36px 22px 80px; }
    header { border-bottom:1px solid #2a2e37; padding-bottom:22px; margin-bottom:28px; }
    header h1 { margin:0 0 4px; font-size:24px; }
    header .sub { color:#9aa2b1; font-size:13px; }
    .meta-grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(160px,1fr)); gap:10px; margin-top:16px; }
    .meta-card { background:#1c1f28; border:1px solid #2a2e37; border-radius:8px; padding:10px 14px; font-size:12px; }
    .meta-card b { display:block; font-size:14px; color:#fff; }
    section { margin:36px 0; }
    h2 { font-size:17px; border-left:4px solid #4fd1c5; padding-left:10px; }
    .chart { width:100%; height:auto; display:block; }
    .chart .barlabel { fill:#c7cdd8; font-size:13px; }
    .chart .barvalue { fill:#ffffff; font-size:13px; font-weight:600; }
    table { width:100%; border-collapse:collapse; font-size:13px; margin-top:10px; }
    th,td { text-align:left; padding:7px 9px; border-bottom:1px solid #2a2e37; }
    th { color:#9aa2b1; text-transform:uppercase; font-size:11px; }
    .pill { padding:2px 10px; border-radius:999px; font-size:12px; font-weight:600; }
    .pill-high{background:#3a1616;color:#f87171;} .pill-med{background:#3a3216;color:#facc15;} .pill-low{background:#16382e;color:#4ade80;}
    .chain { display:flex; flex-wrap:wrap; align-items:center; gap:8px; margin-top:10px; }
    .chain .stage { background:#1c1f28; border:1px solid #4fd1c5; color:#4fd1c5; padding:6px 12px; border-radius:8px; font-size:13px; }
    .chain .arrow { color:#6b7280; }
    .ai-text { background:#1c1f28; border-left:3px solid #818cf8; padding:12px 16px; border-radius:0 8px 8px 0; }
    .ai-note { color:#f87171; font-size:12px; margin-bottom:6px; }
    .muted { color:#6b7280; font-size:13px; }
    ul.findings li { margin-bottom:6px; }
    footer { border-top:1px solid #2a2e37; margin-top:44px; padding-top:16px; color:#6b7280; font-size:11px; }
    """

    # ---- header / metadata ----
    meta_cards = f"""
    <div class="meta-card"><b>{esc(inc.get('severity','UNKNOWN'))}</b>Severity</div>
    <div class="meta-card"><b>{esc(str(stats.get('total_alerts','—')))}</b>Total alerts</div>
    <div class="meta-card"><b>{esc(str(stats.get('detection_latency_seconds','—')))}s</b>Avg. latency</div>
    <div class="meta-card"><b>{esc(ai_meta.get('model','n/a'))}</b>AI model</div>
    <div class="meta-card"><b>{esc(ai_status)}</b>AI status</div>
    <div class="meta-card"><b>{esc(ai_meta.get('cache_status','n/a'))}</b>AI cache</div>
    """

    # ---- attack chain (rendered by app, never by Gemini) ----
    if d.attack_chain:
        stage_html = ""
        for i, stage in enumerate(d.attack_chain):
            if i > 0:
                stage_html += '<span class="arrow">→</span>'
            stage_html += f'<span class="stage">{esc(stage["stage"])} ({stage["confidence"]})</span>'
        chain_html = f'<div class="chain">{stage_html}</div>'
    else:
        chain_html = "<p class='muted'>No correlated attack chain available for this window " \
                     "(run <code>correlate</code> to generate one).</p>"

    # ---- timeline (capped for report readability, same convention as hunt.sh) ----
    timeline_rows = [
        [e["timestamp"], e["source"], e["rule_id"], e["agent"] or "—", e["description"]]
        for e in d.timeline[:30]
    ]

    # ---- detection summary table + chart ----
    det_rows = [[r["test"], r["result"], r["rule"], f'{r["latency_seconds"]}s'] for r in d.detection_results]
    latency_pairs = [(r["test"].split(". ", 1)[-1].split(" (")[0], r["latency_seconds"]) for r in d.detection_results]

    # ---- mitre ----
    mitre_rows = [[m["rule_id"], f'{m["alert_count"]}×', m["tactic"], m["technique_id"], m["technique_name"]]
                  for m in d.mitre_attack]

    # ---- alerts-by-source chart ----
    source_pairs = [("Suricata (network)", stats.get("suricata_alerts", 0)),
                     ("Wazuh (host)", stats.get("wazuh_alerts", 0))]

    # ---- evidence files ----
    evidence_rows = [[f] for f in d.evidence_files]

    findings_html = "".join(f"<li>{esc(f)}</li>" for f in narrative.get("key_findings", [])) or "<li class='muted'>None supplied.</li>"
    limitations_html = "".join(f"<li>{esc(l)}</li>" for l in narrative.get("limitations", [])) or "<li class='muted'>None supplied.</li>"

    html = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<title>{esc(d.report_id)} — NISec Security Report</title>
<style>{css}</style></head>
<body><div class="wrap">

<header>
  <div class="sub">NISec — Centralized Security Monitoring System</div>
  <h1>Security Incident Report {_severity_pill(inc.get('severity','UNKNOWN'))}</h1>
  <div class="sub">Report ID: {esc(d.report_id)} &nbsp;•&nbsp; Generated: {esc(d.generated_at)}</div>
  <div class="meta-grid">{meta_cards}</div>
</header>

<section><h2>Executive Summary</h2>{_ai_block(narrative.get('executive_summary',''), ai_status)}</section>

<section><h2>Incident Overview</h2>
  {_table(["Field","Value"], [
      ["Severity", inc.get("severity","UNKNOWN")],
      ["First observed", inc.get("first_seen") or "—"],
      ["Last observed", inc.get("last_seen") or "—"],
      ["Source IP(s)", ", ".join(inc.get("source_ips") or []) or "—"],
      ["Target host(s)", ", ".join(inc.get("target_hosts") or []) or "—"],
      ["Total alerts", stats.get("total_alerts","—")],
      ["Detection latency (avg)", f'{stats.get("detection_latency_seconds","—")}s'],
  ])}
  {_ai_block(narrative.get('incident_overview',''), ai_status)}
</section>

<section><h2>Attack Chain</h2>
  {chain_html}
  {_ai_block(narrative.get('attack_chain_analysis',''), ai_status)}
</section>

<section><h2>Attack Narrative</h2>{_ai_block(narrative.get('attack_narrative',''), ai_status)}</section>

<section><h2>Timeline</h2>
  {_table(["Timestamp","Source","Rule ID","Agent","Description"], timeline_rows)}
  <p class="muted">Showing up to 30 events. Full data remains in alerts.json on the manager.</p>
</section>

<section><h2>Detection Summary</h2>
  {_table(["Test","Result","Rule","Latency"], det_rows)}
  {_svg_hbar(latency_pairs, "#4fd1c5", "s")}
</section>

<section><h2>Alerts by Source</h2>
  {_svg_hbar(source_pairs, "#818cf8")}
</section>

<section><h2>Detection Analysis</h2>{_ai_block(narrative.get('detection_analysis',''), ai_status)}</section>

<section><h2>MITRE ATT&amp;CK</h2>
  {_table(["Rule ID","Count","Tactic","Technique ID","Technique"], mitre_rows)}
  <p class="muted">Techniques shown are only those already established by the detection/correlation system — Gemini cannot introduce a technique here.</p>
</section>

<section><h2>Evidence</h2>
  {_table(["Source file"], evidence_rows)}
</section>

<section><h2>Key Findings</h2><ul class="findings">{findings_html}</ul></section>

<section><h2>Limitations</h2><ul class="findings">{limitations_html}</ul></section>

<section><h2>Conclusion</h2>{_ai_block(narrative.get('conclusion',''), ai_status)}</section>

<footer>
  Generated by scripts/generate_html_report.py &nbsp;|&nbsp;
  AI model: {esc(ai_meta.get('model','n/a'))} &nbsp;|&nbsp;
  Prompt version: {esc(ai_meta.get('prompt_version','n/a'))} &nbsp;|&nbsp;
  AI status: {esc(ai_status)} &nbsp;|&nbsp;
  Cache: {esc(ai_meta.get('cache_status','n/a'))}<br>
  Deterministic data (tables, charts, IDs, timestamps) is produced entirely by NISec's own
  evidence pipeline. Narrative text sections are AI-authored interpretation of that data and
  are labeled as such; they are never treated as a source of fact.
</footer>

</div></body></html>"""
    return html
