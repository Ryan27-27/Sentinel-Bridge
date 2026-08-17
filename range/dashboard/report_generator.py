"""
Sentinel Range - Dashboard / Report Generator
------------------------------------------------
Joins logs/attack_log.jsonl (red team) with logs/alerts.jsonl (blue team)
by MITRE technique ID, computes Mean Time To Detect (MTTD) per technique,
and renders a static HTML dashboard.
"""
import json
import os
from datetime import datetime
from collections import defaultdict

LOGS_DIR = os.path.join(os.path.dirname(__file__), "..", "logs")
ATTACK_LOG = os.path.join(LOGS_DIR, "attack_log.jsonl")
ALERTS_LOG = os.path.join(LOGS_DIR, "alerts.jsonl")
OUTPUT_HTML = os.path.join(os.path.dirname(__file__), "dashboard.html")


def load_jsonl(path):
    if not os.path.exists(path):
        return []
    with open(path) as f:
        return [json.loads(line) for line in f if line.strip()]


def parse_ts(ts):
    return datetime.fromisoformat(ts)


def build_report():
    attacks = load_jsonl(ATTACK_LOG)
    alerts = load_jsonl(ALERTS_LOG)

    # group first-seen attack time and first-seen alert time per technique
    first_attack = {}
    for a in attacks:
        tid = a["mitre_technique_id"]
        ts = parse_ts(a["timestamp"])
        if tid not in first_attack or ts < first_attack[tid]:
            first_attack[tid] = ts

    first_alert = {}
    alert_by_tid = defaultdict(list)
    for al in alerts:
        tid = al["mitre_technique_id"]
        ts = parse_ts(al["timestamp"])
        alert_by_tid[tid].append(al)
        if tid not in first_alert or ts < first_alert[tid]:
            first_alert[tid] = ts

    technique_names = {}
    for a in attacks:
        technique_names[a["mitre_technique_id"]] = a["mitre_technique_name"]

    rows = []
    detected_count = 0
    mttd_values = []
    for tid, atime in sorted(first_attack.items()):
        name = technique_names.get(tid, "")
        if tid in first_alert:
            mttd = (first_alert[tid] - atime).total_seconds()
            mttd = max(mttd, 0)
            mttd_values.append(mttd)
            detected_count += 1
            status = "DETECTED"
        else:
            mttd = None
            status = "MISSED"
        rows.append(
            {
                "tid": tid,
                "name": name,
                "attack_time": atime.isoformat(),
                "status": status,
                "mttd": f"{mttd:.2f}s" if mttd is not None else "-",
                "alert_count": len(alert_by_tid.get(tid, [])),
            }
        )

    total_techniques = len(first_attack)
    detection_rate = (detected_count / total_techniques * 100) if total_techniques else 0
    avg_mttd = (sum(mttd_values) / len(mttd_values)) if mttd_values else None

    html = render_html(rows, total_techniques, detected_count, detection_rate, avg_mttd)
    with open(OUTPUT_HTML, "w") as f:
        f.write(html)
    print(f"Dashboard written to {OUTPUT_HTML}")
    print(f"Detection rate: {detection_rate:.0f}% ({detected_count}/{total_techniques})")
    if avg_mttd is not None:
        print(f"Average MTTD: {avg_mttd:.2f}s")


def render_html(rows, total, detected, rate, avg_mttd):
    row_html = ""
    for r in rows:
        badge_color = "#1a7f37" if r["status"] == "DETECTED" else "#c62828"
        row_html += f"""
        <tr>
          <td>{r['tid']}</td>
          <td>{r['name']}</td>
          <td>{r['attack_time']}</td>
          <td><span style="color:{badge_color};font-weight:600;">{r['status']}</span></td>
          <td>{r['mttd']}</td>
          <td>{r['alert_count']}</td>
        </tr>"""

    avg_mttd_str = f"{avg_mttd:.2f}s" if avg_mttd is not None else "N/A"

    return f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>Sentinel Range — Purple Team Dashboard</title>
<style>
  body {{ font-family: -apple-system, Segoe UI, Roboto, sans-serif; background:#0d1117; color:#e6edf3; margin:0; padding:32px; }}
  h1 {{ font-size:22px; margin-bottom:4px; }}
  .sub {{ color:#8b949e; margin-bottom:24px; }}
  .stats {{ display:flex; gap:16px; margin-bottom:24px; }}
  .card {{ background:#161b22; border:1px solid #30363d; border-radius:8px; padding:16px 20px; flex:1; }}
  .card .label {{ color:#8b949e; font-size:12px; text-transform:uppercase; }}
  .card .value {{ font-size:26px; font-weight:700; margin-top:4px; }}
  table {{ width:100%; border-collapse:collapse; background:#161b22; border:1px solid #30363d; border-radius:8px; overflow:hidden; }}
  th, td {{ text-align:left; padding:10px 14px; border-bottom:1px solid #30363d; font-size:13px; }}
  th {{ background:#0d1117; color:#8b949e; text-transform:uppercase; font-size:11px; }}
  tr:last-child td {{ border-bottom:none; }}
</style>
</head>
<body>
  <h1>Sentinel Range — Purple Team Dashboard</h1>
  <div class="sub">Red-team attack chain vs. blue-team detection engine, mapped to MITRE ATT&amp;CK</div>
  <div class="stats">
    <div class="card"><div class="label">Techniques Attempted</div><div class="value">{total}</div></div>
    <div class="card"><div class="label">Detected</div><div class="value">{detected}/{total}</div></div>
    <div class="card"><div class="label">Detection Rate</div><div class="value">{rate:.0f}%</div></div>
    <div class="card"><div class="label">Avg. MTTD</div><div class="value">{avg_mttd_str}</div></div>
  </div>
  <table>
    <thead><tr><th>ATT&amp;CK ID</th><th>Technique</th><th>First Attack Time (UTC)</th><th>Status</th><th>MTTD</th><th>Alerts Fired</th></tr></thead>
    <tbody>{row_html}
    </tbody>
  </table>
</body>
</html>"""


if __name__ == "__main__":
    build_report()
