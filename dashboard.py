"""Local-only web dashboard for SOC incident records.

Run this module after generating incidents with ``main.py`` and open the URL it
prints. The server binds to 127.0.0.1 by default, so it is available only on the
same computer and does not transmit incident data anywhere.
"""

from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime
import html
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parent
DEFAULT_INCIDENTS_DIR = PROJECT_ROOT / "incidents"
SEVERITIES = ("high", "medium", "low")


def load_incidents(incidents_dir: Path) -> list[dict[str, Any]]:
    """Read valid local incident JSON records, newest first.

    A malformed JSON file is skipped so one bad record cannot stop the local
    dashboard from loading the remaining incident history.
    """
    if not incidents_dir.exists():
        return []

    incidents: list[dict[str, Any]] = []
    for path in incidents_dir.glob("*.json"):
        try:
            with path.open("r", encoding="utf-8") as incident_file:
                incident = json.load(incident_file)
        except (OSError, json.JSONDecodeError):
            continue
        if isinstance(incident, dict):
            incidents.append(incident)

    return sorted(incidents, key=lambda incident: str(incident.get("created_at", "")), reverse=True)


def safe_text(value: Any, default: str = "—") -> str:
    """Return escaped text suitable for placement in the HTML page."""
    if value in (None, ""):
        return default
    return html.escape(str(value))


def format_time(value: Any) -> str:
    """Format an ISO timestamp for the dashboard, retaining a safe fallback."""
    if not value:
        return "—"
    try:
        return datetime.fromisoformat(str(value)).strftime("%d %b %Y, %H:%M UTC")
    except ValueError:
        return safe_text(value)


def severity_badge(severity: Any) -> str:
    normalized = str(severity).lower()
    css_class = normalized if normalized in SEVERITIES else "unknown"
    label = normalized.upper() if normalized else "UNKNOWN"
    return f'<span class="badge {css_class}">{html.escape(label)}</span>'


def render_incident_rows(incidents: list[dict[str, Any]]) -> str:
    rows: list[str] = []
    for incident in incidents:
        risk = incident.get("risk") if isinstance(incident.get("risk"), dict) else {}
        evidence = incident.get("evidence") if isinstance(incident.get("evidence"), list) else []
        incident_id = safe_text(incident.get("incident_id"))
        source_ip = safe_text(incident.get("source_ip"))
        score = safe_text(risk.get("score"))
        severity = severity_badge(risk.get("severity"))
        created_at = format_time(incident.get("created_at"))
        reasons = risk.get("reasons") if isinstance(risk.get("reasons"), list) else []
        reason_items = "".join(f"<li>{safe_text(reason)}</li>" for reason in reasons)
        evidence_rows = "".join(
            "<tr>"
            f"<td>{safe_text(event.get('timestamp'))}</td>"
            f"<td>{safe_text(event.get('username'))}</td>"
            f"<td>{'Yes' if event.get('invalid_user') else 'No'}</td>"
            "</tr>"
            for event in evidence
            if isinstance(event, dict)
        ) or '<tr><td colspan="3">No evidence was recorded.</td></tr>'
        next_step = safe_text(incident.get("recommended_next_step"))

        rows.append(
            "<tr>"
            f"<td><strong>{incident_id}</strong><span class=\"muted\">{created_at}</span></td>"
            f"<td>{source_ip}</td>"
            f"<td>{severity}</td>"
            f"<td><strong>{score}</strong><span class=\"muted\">/100</span></td>"
            f"<td>{len(evidence)}</td>"
            "<td>"
            "<details><summary>View</summary>"
            f"<p class=\"next-step\"><strong>Suggested review:</strong> {next_step}</p>"
            f"<p><strong>Risk reasons</strong></p><ul>{reason_items or '<li>None recorded</li>'}</ul>"
            "<div class=\"evidence-wrap\"><table class=\"evidence-table\">"
            "<thead><tr><th>Timestamp</th><th>Account</th><th>Invalid account</th></tr></thead>"
            f"<tbody>{evidence_rows}</tbody></table></div>"
            "</details>"
            "</td>"
            "</tr>"
        )
    return "".join(rows)


def render_risk_bars(incidents: list[dict[str, Any]]) -> str:
    if not incidents:
        return '<p class="empty">Run <code>main.py</code> to create local incident records.</p>'

    bars: list[str] = []
    for incident in incidents[:8]:
        risk = incident.get("risk") if isinstance(incident.get("risk"), dict) else {}
        try:
            score = max(0, min(100, int(risk.get("score", 0))))
        except (TypeError, ValueError):
            score = 0
        severity = str(risk.get("severity", "unknown")).lower()
        css_class = severity if severity in SEVERITIES else "unknown"
        bars.append(
            '<div class="risk-row">'
            f'<span title="{safe_text(incident.get("incident_id"))}">{safe_text(incident.get("source_ip"))}</span>'
            f'<div class="bar-track"><div class="bar {css_class}" style="width: {score}%"></div></div>'
            f'<strong>{score}</strong>'
            "</div>"
        )
    return "".join(bars)


def render_dashboard(incidents: list[dict[str, Any]]) -> str:
    """Render an HTML dashboard from local incident records."""
    severity_counts = Counter(
        str((incident.get("risk") or {}).get("severity", "unknown")).lower()
        for incident in incidents
        if isinstance(incident.get("risk"), dict)
    )
    average_risk = (
        round(
            sum(
                int((incident.get("risk") or {}).get("score", 0))
                for incident in incidents
                if isinstance(incident.get("risk"), dict)
            )
            / len(incidents)
        )
        if incidents
        else 0
    )
    latest_update = format_time(incidents[0].get("created_at")) if incidents else "No records yet"
    rows = render_incident_rows(incidents)
    table_body = rows or '<tr><td colspan="6" class="empty">No incident JSON files found yet.</td></tr>'

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta http-equiv="refresh" content="30">
  <title>Sentinel Desk | Local SOC Dashboard</title>
  <style>
    :root {{ --bg: #0b1220; --panel: #111c30; --panel-alt: #172640; --text: #edf3ff; --muted: #9bb0d0; --line: #2a3b59; --cyan: #55d7ff; --high: #fb7185; --medium: #fbbf24; --low: #38d39f; }}
    * {{ box-sizing: border-box; }}
    body {{ margin: 0; font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; background: radial-gradient(circle at 15% 0%, #173463, transparent 34%), var(--bg); color: var(--text); }}
    .shell {{ max-width: 1280px; margin: 0 auto; padding: 34px 24px 56px; }}
    header {{ display: flex; align-items: flex-start; justify-content: space-between; gap: 24px; margin-bottom: 28px; }}
    .eyebrow {{ color: var(--cyan); font-size: .75rem; font-weight: 800; letter-spacing: .13em; text-transform: uppercase; margin: 0 0 8px; }}
    h1 {{ font-size: clamp(1.7rem, 4vw, 2.5rem); margin: 0; letter-spacing: -.03em; }}
    .subhead {{ color: var(--muted); margin: 8px 0 0; max-width: 680px; line-height: 1.55; }}
    .local-tag {{ border: 1px solid #27638a; color: #a5e7ff; background: #112b43; border-radius: 999px; padding: 8px 12px; font-size: .8rem; white-space: nowrap; }}
    .metrics {{ display: grid; grid-template-columns: repeat(5, minmax(0, 1fr)); gap: 14px; margin-bottom: 18px; }}
    .metric, .panel {{ background: linear-gradient(145deg, rgba(23,38,64,.92), rgba(15,27,47,.92)); border: 1px solid var(--line); border-radius: 16px; box-shadow: 0 14px 34px rgba(0,0,0,.18); }}
    .metric {{ padding: 18px; }}
    .metric-label {{ color: var(--muted); font-size: .78rem; font-weight: 700; letter-spacing: .06em; text-transform: uppercase; }}
    .metric-value {{ display: block; margin-top: 8px; font-size: 2rem; font-weight: 800; }}
    .metric.high .metric-value {{ color: var(--high); }} .metric.medium .metric-value {{ color: var(--medium); }} .metric.low .metric-value {{ color: var(--low); }}
    .grid {{ display: grid; grid-template-columns: minmax(0, 1.4fr) minmax(280px, .6fr); gap: 18px; margin-bottom: 18px; }}
    .panel {{ padding: 22px; }} .panel h2 {{ font-size: 1rem; margin: 0 0 4px; }} .panel-note {{ color: var(--muted); font-size: .85rem; margin: 0 0 20px; }}
    .risk-row {{ display: grid; grid-template-columns: 120px 1fr 38px; gap: 10px; align-items: center; margin: 13px 0; font-size: .88rem; }}
    .risk-row > span {{ overflow: hidden; text-overflow: ellipsis; white-space: nowrap; color: #c8d7ee; }}
    .bar-track {{ height: 9px; border-radius: 999px; background: #0b1425; overflow: hidden; }} .bar {{ height: 100%; border-radius: inherit; background: var(--cyan); }} .bar.high {{ background: var(--high); }} .bar.medium {{ background: var(--medium); }} .bar.low {{ background: var(--low); }}
    .callout {{ border-left: 3px solid var(--cyan); padding: 4px 0 4px 14px; color: var(--muted); line-height: 1.55; font-size: .9rem; }} .callout strong {{ color: var(--text); }}
    .table-panel {{ overflow: hidden; padding: 0; }} .table-heading {{ padding: 22px 22px 14px; display: flex; justify-content: space-between; gap: 12px; align-items: baseline; }} .updated {{ color: var(--muted); font-size: .8rem; }}
    .table-wrap {{ overflow-x: auto; }} table {{ width: 100%; border-collapse: collapse; min-width: 860px; }} th, td {{ padding: 15px 22px; border-top: 1px solid var(--line); text-align: left; vertical-align: top; font-size: .9rem; }} th {{ color: var(--muted); font-size: .73rem; letter-spacing: .08em; text-transform: uppercase; background: rgba(8,17,33,.25); }}
    .muted {{ display: block; color: var(--muted); font-size: .76rem; margin-top: 3px; }} .badge {{ display: inline-block; border-radius: 999px; padding: 5px 9px; font-size: .7rem; font-weight: 800; letter-spacing: .06em; }} .badge.high {{ color: #fecdd3; background: #4c1d2a; }} .badge.medium {{ color: #fef3c7; background: #4a3510; }} .badge.low {{ color: #bbf7d0; background: #123b32; }} .badge.unknown {{ color: #cbd5e1; background: #334155; }}
    details {{ color: var(--muted); }} summary {{ cursor: pointer; color: var(--cyan); font-weight: 700; }} details p {{ margin: 12px 0 8px; }} details ul {{ margin: 6px 0 14px; padding-left: 18px; }} .next-step {{ line-height: 1.45; }} .evidence-wrap {{ border: 1px solid var(--line); border-radius: 8px; overflow: hidden; }} .evidence-table {{ min-width: 460px; }} .evidence-table th, .evidence-table td {{ padding: 8px 10px; font-size: .78rem; }}
    .empty {{ color: var(--muted); text-align: center; padding: 26px; }} code {{ background: #0a172b; color: #bceaff; padding: 2px 5px; border-radius: 4px; }} footer {{ color: #7890b2; font-size: .78rem; margin-top: 15px; }}
    @media (max-width: 940px) {{ .metrics {{ grid-template-columns: repeat(3, 1fr); }} .grid {{ grid-template-columns: 1fr; }} }} @media (max-width: 620px) {{ .shell {{ padding: 24px 14px 40px; }} header {{ display: block; }} .local-tag {{ display: inline-block; margin-top: 14px; }} .metrics {{ grid-template-columns: repeat(2, 1fr); }} .metric:first-child {{ grid-column: span 2; }} }}
  </style>
</head>
<body>
  <main class="shell">
    <header>
      <div><p class="eyebrow">Defensive lab environment</p><h1>Sentinel Desk</h1><p class="subhead">Local incident overview for repeated SSH login failures. Refreshes every 30 seconds while the dashboard is open.</p></div>
      <span class="local-tag">● Local-only server</span>
    </header>

    <section class="metrics" aria-label="Incident metrics">
      <div class="metric"><span class="metric-label">Total incidents</span><strong class="metric-value">{len(incidents)}</strong></div>
      <div class="metric high"><span class="metric-label">High</span><strong class="metric-value">{severity_counts['high']}</strong></div>
      <div class="metric medium"><span class="metric-label">Medium</span><strong class="metric-value">{severity_counts['medium']}</strong></div>
      <div class="metric low"><span class="metric-label">Low</span><strong class="metric-value">{severity_counts['low']}</strong></div>
      <div class="metric"><span class="metric-label">Average risk</span><strong class="metric-value">{average_risk}<small>/100</small></strong></div>
    </section>

    <section class="grid">
      <article class="panel"><h2>Risk by incident</h2><p class="panel-note">Newest eight local records</p>{render_risk_bars(incidents)}</article>
      <aside class="panel"><h2>Safety boundary</h2><p class="panel-note">What this dashboard does</p><div class="callout"><strong>Read-only visualisation.</strong><br>It reads JSON records from the local <code>incidents/</code> folder. It does not block addresses, modify accounts, send alerts, or contact external services.</div></aside>
    </section>

    <section class="panel table-panel">
      <div class="table-heading"><div><h2>Incident queue</h2><p class="panel-note">Expand a record to review its evidence and triage rationale.</p></div><span class="updated">Updated: {latest_update}</span></div>
      <div class="table-wrap"><table><thead><tr><th>Incident</th><th>Source IP</th><th>Severity</th><th>Risk</th><th>Events</th><th>Evidence</th></tr></thead><tbody>{table_body}</tbody></table></div>
    </section>
    <footer>Sentinel Desk is a local lab dashboard. Risk scores support analyst triage and are not proof of malicious activity.</footer>
  </main>
</body>
</html>"""


class DashboardHandler(BaseHTTPRequestHandler):
    """Serve the dashboard without exposing arbitrary local files."""

    incidents_dir = DEFAULT_INCIDENTS_DIR

    def do_GET(self) -> None:  # noqa: N802 - name mandated by BaseHTTPRequestHandler
        if self.path == "/health":
            self._send_response(200, "text/plain; charset=utf-8", "ok\n")
            return
        if self.path != "/":
            self._send_response(404, "text/plain; charset=utf-8", "Not found\n")
            return
        self._send_response(200, "text/html; charset=utf-8", render_dashboard(load_incidents(self.incidents_dir)))

    def _send_response(self, status: int, content_type: str, content: str) -> None:
        body = content.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'unsafe-inline'; base-uri 'none'")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        """Keep normal page-refresh logs out of the user's terminal."""


def main() -> int:
    parser = argparse.ArgumentParser(description="Serve the local SOC incident dashboard.")
    parser.add_argument("--incidents-dir", type=Path, default=DEFAULT_INCIDENTS_DIR)
    parser.add_argument("--host", default="127.0.0.1", help="Local bind address (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8080, help="Local port (default: 8080)")
    args = parser.parse_args()

    DashboardHandler.incidents_dir = args.incidents_dir
    server = ThreadingHTTPServer((args.host, args.port), DashboardHandler)
    print(f"Dashboard ready at http://{args.host}:{args.port}")
    print(f"Reading local incident records from: {args.incidents_dir.resolve()}")
    print("Press Ctrl+C to stop the local server.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nDashboard stopped.")
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
