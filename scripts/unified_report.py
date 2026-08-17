"""
Sentinel — Unified ATT&CK Coverage Report
------------------------------------------
Joins the two halves of the platform on one axis: the MITRE ATT&CK technique ID.

  pipeline/   -> "did we find this vulnerability class before release?"
                 (SAST/DAST/secrets findings, each carrying an attack_id via
                 pipeline/scanner/attack_mapping.py)
  range/      -> "if someone exploits this class at runtime, do we detect it,
                 and how fast?" (attack_log.jsonl vs alerts.jsonl, joined by
                 mitre_technique_id in range/dashboard/report_generator.py)

Run from the repo root:
    python3 scripts/unified_report.py

Output: scripts/unified_dashboard.html
Falls back to range/sample_run/*.jsonl if range/logs/ is empty (i.e. you
haven't run a live attack chain yet), so the report works out of the box.
"""
import json
import os
import sys
from datetime import datetime
from collections import defaultdict

ROOT = os.path.dirname(os.path.abspath(__file__))
PIPELINE_DIR = os.path.join(ROOT, "..", "pipeline")
RANGE_DIR = os.path.join(ROOT, "..", "range")
OUTPUT_HTML = os.path.join(ROOT, "unified_dashboard.html")

sys.path.insert(0, PIPELINE_DIR)
from aggregator.db import Database          # noqa: E402
from scanner.attack_mapping import attack_id_for, CWE_TO_ATTACK  # noqa: E402


def load_jsonl(path):
    if not os.path.exists(path):
        return []
    with open(path) as f:
        return [json.loads(line) for line in f if line.strip()]


def parse_ts(ts):
    return datetime.fromisoformat(ts)


def load_pipeline_findings():
    """Pull open vulnerabilities from the pipeline DB (auto-seeded on first run)
    and tag each with its ATT&CK technique ID."""
    db = Database()
    vulns = db.get_vulns(severity="all", status="open", limit=500)
    by_technique = defaultdict(list)
    for v in vulns:
        tid = attack_id_for(v.get("cwe", ""))
        if tid:
            by_technique[tid].append(v)
    return by_technique


def load_range_results():
    """Join range's attack_log.jsonl / alerts.jsonl by technique, same logic as
    range/dashboard/report_generator.py. Prefers live logs/, falls back to the
    checked-in sample_run/ so this works with zero setup."""
    logs_dir = os.path.join(RANGE_DIR, "logs")
    sample_dir = os.path.join(RANGE_DIR, "sample_run")
    attack_path = os.path.join(logs_dir, "attack_log.jsonl")
    source_dir = logs_dir if os.path.exists(attack_path) and load_jsonl(attack_path) else sample_dir

    attacks = load_jsonl(os.path.join(source_dir, "attack_log.jsonl"))
    alerts = load_jsonl(os.path.join(source_dir, "alerts.jsonl"))

    first_attack, first_alert, names, alert_counts = {}, {}, {}, defaultdict(int)
    for a in attacks:
        tid = a["mitre_technique_id"]
        names[tid] = a["mitre_technique_name"]
        ts = parse_ts(a["timestamp"])
        if tid not in first_attack or ts < first_attack[tid]:
            first_attack[tid] = ts
    for al in alerts:
        tid = al["mitre_technique_id"]
        alert_counts[tid] += 1
        ts = parse_ts(al["timestamp"])
        if tid not in first_alert or ts < first_alert[tid]:
            first_alert[tid] = ts

    results = {}
    for tid, atime in first_attack.items():
        if tid in first_alert:
            mttd = max((first_alert[tid] - atime).total_seconds(), 0)
            results[tid] = {"status": "DETECTED", "mttd": f"{mttd:.2f}s", "alerts": alert_counts[tid], "name": names.get(tid, "")}
        else:
            results[tid] = {"status": "MISSED", "mttd": "-", "alerts": 0, "name": names.get(tid, "")}
    return results, (source_dir == sample_dir)


def technique_name(tid, range_results, pipeline_findings):
    if tid in range_results and range_results[tid]["name"]:
        return range_results[tid]["name"]
    entry = CWE_TO_ATTACK  # tid -> (id, label); invert lookup isn't needed, just use pipeline finding titles
    for v in pipeline_findings.get(tid, []):
        return v.get("title", "")
    return ""


def build():
    pipeline_findings = load_pipeline_findings()
    range_results, used_sample = load_range_results()

    all_ids = sorted(set(pipeline_findings.keys()) | set(range_results.keys()))

    rows = []
    for tid in all_ids:
        p_hits = pipeline_findings.get(tid, [])
        r = range_results.get(tid)
        rows.append({
            "tid": tid,
            "name": technique_name(tid, range_results, pipeline_findings),
            "pipeline_found": len(p_hits) > 0,
            "pipeline_detail": "; ".join(f"{v['severity'].upper()} {v.get('cwe','')} @ {v['location']}" for v in p_hits[:3]),
            "range_status": r["status"] if r else "NOT ATTEMPTED",
            "mttd": r["mttd"] if r else "-",
            "both": (len(p_hits) > 0 and r is not None),
        })

    total_techniques = len(rows)
    caught_pre_release = sum(1 for r in rows if r["pipeline_found"])
    caught_at_runtime = sum(1 for r in rows if r["range_status"] == "DETECTED")
    covered_both_sides = sum(1 for r in rows if r["both"])

    html = render_html(rows, total_techniques, caught_pre_release, caught_at_runtime, covered_both_sides, used_sample)
    with open(OUTPUT_HTML, "w") as f:
        f.write(html)
    print(f"Unified dashboard written to {OUTPUT_HTML}")
    print(f"Techniques tracked: {total_techniques} | pre-release: {caught_pre_release} | "
          f"runtime-detected: {caught_at_runtime} | covered on both sides: {covered_both_sides}")
    if used_sample:
        print("(range/logs/ was empty — used the checked-in range/sample_run/ data. "
              "Run the live attack chain in range/ and re-run this script for fresh numbers.)")


def render_html(rows, total, pre_release, runtime, both, used_sample):
    row_html = ""
    for r in rows:
        pipe_badge = ('<span style="color:#1a7f37;font-weight:600;">FOUND</span>' if r["pipeline_found"]
                      else '<span style="color:#8b949e;">not scanned</span>')
        range_color = {"DETECTED": "#1a7f37", "MISSED": "#c62828", "NOT ATTEMPTED": "#8b949e"}[r["range_status"]]
        row_html += f"""
        <tr>
          <td>{r['tid']}</td>
          <td>{r['name']}</td>
          <td>{pipe_badge}<div class="detail">{r['pipeline_detail']}</div></td>
          <td><span style="color:{range_color};font-weight:600;">{r['range_status']}</span></td>
          <td>{r['mttd']}</td>
          <td>{'✓' if r['both'] else ''}</td>
        </tr>"""

    note = ("<div class='note'>Range figures are from the checked-in sample_run/ data — "
            "run the live attack chain for fresh numbers.</div>" if used_sample else "")

    return f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>Sentinel — Unified ATT&amp;CK Coverage</title>
<style>
  body {{ font-family: -apple-system, Segoe UI, Roboto, sans-serif; background:#0d1117; color:#e6edf3; margin:0; padding:32px; }}
  h1 {{ font-size:22px; margin-bottom:4px; }}
  .sub {{ color:#8b949e; margin-bottom:24px; }}
  .note {{ color:#c9a227; font-size:12px; margin-bottom:16px; }}
  .stats {{ display:flex; gap:16px; margin-bottom:24px; }}
  .card {{ background:#161b22; border:1px solid #30363d; border-radius:8px; padding:16px 20px; flex:1; }}
  .card .label {{ color:#8b949e; font-size:12px; text-transform:uppercase; }}
  .card .value {{ font-size:26px; font-weight:700; margin-top:4px; }}
  table {{ width:100%; border-collapse:collapse; background:#161b22; border:1px solid #30363d; border-radius:8px; overflow:hidden; }}
  th, td {{ text-align:left; padding:10px 14px; border-bottom:1px solid #30363d; font-size:13px; vertical-align:top; }}
  th {{ background:#0d1117; color:#8b949e; text-transform:uppercase; font-size:11px; }}
  tr:last-child td {{ border-bottom:none; }}
  .detail {{ color:#8b949e; font-size:11px; margin-top:2px; }}
</style>
</head>
<body>
  <h1>Sentinel — Unified ATT&amp;CK Coverage</h1>
  <div class="sub">Pipeline (pre-release scanning) joined with Range (live attack/detection) by MITRE ATT&amp;CK technique ID</div>
  {note}
  <div class="stats">
    <div class="card"><div class="label">Techniques Tracked</div><div class="value">{total}</div></div>
    <div class="card"><div class="label">Found Pre-Release</div><div class="value">{pre_release}/{total}</div></div>
    <div class="card"><div class="label">Detected at Runtime</div><div class="value">{runtime}/{total}</div></div>
    <div class="card"><div class="label">Covered Both Sides</div><div class="value">{both}/{total}</div></div>
  </div>
  <table>
    <thead><tr><th>ATT&amp;CK ID</th><th>Technique</th><th>Pipeline (pre-release)</th><th>Range (runtime)</th><th>MTTD</th><th>Both</th></tr></thead>
    <tbody>{row_html}
    </tbody>
  </table>
</body>
</html>"""


if __name__ == "__main__":
    build()
