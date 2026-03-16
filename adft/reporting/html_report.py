from __future__ import annotations

import html
import json
from pathlib import Path
from typing import Any, Dict

from adft import RELEASE_LABEL
from adft.reporting.json_report import JSONReportGenerator


def _esc(value: Any) -> str:
    return html.escape(str(value if value is not None else ""), quote=True)


class HTMLReportGenerator:
    """Generate a standalone single-file HTML report without any interface dependency."""

    def __init__(self) -> None:
        self._json = JSONReportGenerator()

    def generate(self, report: Any, output_path: Path) -> None:
        data = self._serialize(report)
        output_path.write_text(self._render_html(data), encoding="utf-8")

    def _serialize(self, report: Any) -> Dict[str, Any]:
        if isinstance(report, dict):
            return report
        if hasattr(self._json, "_serialize_report"):
            return self._json._serialize_report(report)  # type: ignore[attr-defined]
        return {
            "metadata": {"title": f"ADFT Investigation Report {RELEASE_LABEL}"},
            "alerts": [],
            "timeline": {"entries": []},
            "security_score": {},
        }

    def _render_html(self, data: Dict[str, Any]) -> str:
        metadata = data.get("metadata") or {}
        stats = data.get("stats") or {}
        score = data.get("security_score") or {}
        alerts = list(data.get("alerts") or [])[:50]
        timeline = list((data.get("timeline") or {}).get("entries") or [])[:80]
        investigations = list(data.get("investigations") or [])[:20]
        hardening = list((data.get("hardening") or {}).get("findings") or [])[:30]
        title = metadata.get("title") or f"ADFT Investigation Report {RELEASE_LABEL}"
        risk = score.get("risk_level") or score.get("level") or "unknown"
        value = score.get("global_score") if score.get("global_score") is not None else score.get("score")
        summary = score.get("summary") or ((data.get("case_explanation") or {}).get("summary")) or "No summary available."

        def render_alert_rows() -> str:
            if not alerts:
                return '<tr><td colspan="6">No alerts in this report.</td></tr>'
            rows = []
            for item in alerts:
                rows.append(
                    "<tr>"
                    f"<td>{_esc(item.get('timestamp') or '')}</td>"
                    f"<td>{_esc(item.get('severity') or '')}</td>"
                    f"<td>{_esc(item.get('rule_name') or item.get('rule_id') or '')}</td>"
                    f"<td>{_esc(item.get('user') or '')}</td>"
                    f"<td>{_esc(item.get('source_host') or item.get('host') or '')}</td>"
                    f"<td>{_esc(item.get('mitre_technique') or '')}</td>"
                    "</tr>"
                )
            return ''.join(rows)

        def render_timeline_rows() -> str:
            if not timeline:
                return '<tr><td colspan="4">No timeline entries.</td></tr>'
            rows = []
            for item in timeline:
                rows.append(
                    "<tr>"
                    f"<td>{_esc(item.get('timestamp') or '')}</td>"
                    f"<td>{_esc(item.get('phase') or '')}</td>"
                    f"<td>{_esc(item.get('title') or '')}</td>"
                    f"<td>{_esc(item.get('description') or '')}</td>"
                    "</tr>"
                )
            return ''.join(rows)

        def render_cards(items: list[dict], empty_label: str, title_key: str = "title") -> str:
            if not items:
                return f'<div class="empty">{_esc(empty_label)}</div>'
            blocks = []
            for item in items:
                blocks.append(
                    '<div class="card inner">'
                    f"<h3>{_esc(item.get(title_key) or item.get('finding_id') or item.get('name') or 'Item')}</h3>"
                    f"<p>{_esc(item.get('summary') or item.get('description') or '')}</p>"
                    '</div>'
                )
            return ''.join(blocks)

        raw_json = html.escape(json.dumps(data, ensure_ascii=False, indent=2))
        return f'''<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>{_esc(title)}</title>
  <style>
    :root {{
      --bg:#0b1020; --surface:#121a2b; --surface2:#182338; --border:#24324a;
      --text:#e8eef8; --muted:#9fb0c7; --primary:#4da3ff;
    }}
    * {{ box-sizing:border-box; }}
    body {{ margin:0; background:var(--bg); color:var(--text); font:14px/1.55 Inter, sans-serif; }}
    .wrap {{ max-width:1200px; margin:0 auto; padding:24px; }}
    .hero {{ background:linear-gradient(180deg, var(--surface), var(--surface2)); border:1px solid var(--border); border-radius:20px; padding:24px; }}
    h1,h2,h3 {{ margin:0 0 10px; }}
    .meta,.summary,.empty {{ color:var(--muted); }}
    .grid {{ display:grid; gap:16px; }}
    .kpis {{ grid-template-columns:repeat(auto-fit,minmax(180px,1fr)); margin-top:18px; }}
    .dual {{ grid-template-columns:repeat(auto-fit,minmax(300px,1fr)); }}
    .card {{ background:var(--surface); border:1px solid var(--border); border-radius:18px; padding:18px; }}
    .card.inner {{ margin-bottom:12px; }}
    .label {{ color:var(--muted); font-size:12px; text-transform:uppercase; letter-spacing:.08em; }}
    .value {{ font-size:30px; font-weight:700; margin-top:6px; }}
    .section {{ margin-top:18px; }}
    table {{ width:100%; border-collapse:collapse; font-size:13px; }}
    th,td {{ text-align:left; padding:10px 12px; border-bottom:1px solid var(--border); vertical-align:top; }}
    th {{ color:var(--muted); font-weight:600; }}
    .badge {{ display:inline-block; padding:4px 10px; border-radius:999px; font-size:12px; font-weight:600; background:rgba(77,163,255,.12); color:var(--primary); }}
    pre {{ white-space:pre-wrap; word-break:break-word; background:var(--surface); border:1px solid var(--border); border-radius:18px; padding:18px; overflow:auto; }}
  </style>
</head>
<body>
  <div class="wrap">
    <section class="hero">
      <div class="badge">ADFT {RELEASE_LABEL}</div>
      <h1>{_esc(title)}</h1>
      <p class="summary">{_esc(summary)}</p>
      <div class="meta">Date: {_esc(metadata.get('date') or data.get('date') or '')} · Risk: {_esc(risk)} · Score: {_esc(value if value is not None else 'n/a')}</div>
      <div class="grid kpis">
        <div class="card"><div class="label">Events analyzed</div><div class="value">{_esc(stats.get('raw_events', 0))}</div></div>
        <div class="card"><div class="label">Alerts</div><div class="value">{_esc(stats.get('alerts', len(data.get('alerts') or [])))}</div></div>
        <div class="card"><div class="label">Investigations</div><div class="value">{_esc(stats.get('investigations', len(data.get('investigations') or [])))}</div></div>
        <div class="card"><div class="label">Timeline entries</div><div class="value">{_esc(stats.get('timeline_entries', len((data.get('timeline') or {}).get('entries') or [])))}</div></div>
      </div>
    </section>

    <section class="section card">
      <h2>Alerts</h2>
      <table>
        <thead><tr><th>Timestamp</th><th>Severity</th><th>Rule</th><th>User</th><th>Host</th><th>Technique</th></tr></thead>
        <tbody>{render_alert_rows()}</tbody>
      </table>
    </section>

    <section class="section card">
      <h2>Timeline</h2>
      <table>
        <thead><tr><th>Timestamp</th><th>Phase</th><th>Title</th><th>Description</th></tr></thead>
        <tbody>{render_timeline_rows()}</tbody>
      </table>
    </section>

    <section class="section grid dual">
      <div class="card"><h2>Investigations</h2>{render_cards(investigations, 'No investigations generated.')}</div>
      <div class="card"><h2>Hardening</h2>{render_cards(hardening, 'No hardening findings.')}</div>
    </section>

    <section class="section">
      <h2>Embedded JSON</h2>
      <pre>{raw_json}</pre>
    </section>
  </div>
</body>
</html>'''
