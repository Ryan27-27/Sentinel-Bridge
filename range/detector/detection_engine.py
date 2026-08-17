"""
Sentinel Range - Detection Engine
------------------------------------
Blue-team component. Tails the vulnerable app's structured access log
(logs/access.jsonl) and applies signature/heuristic rules to detect the
three seeded attack classes, writing alerts to logs/alerts.jsonl with
MITRE ATT&CK technique mapping and severity.

Run modes:
  --once      analyze whatever is currently in the log and exit
  --follow    tail the log continuously (like a real SIEM ingest pipeline)
"""
import argparse
import json
import os
import re
import time
from collections import defaultdict
from datetime import datetime, timezone

ACCESS_LOG = os.path.join(os.path.dirname(__file__), "..", "logs", "access.jsonl")
ALERTS_LOG = os.path.join(os.path.dirname(__file__), "..", "logs", "alerts.jsonl")

SQLI_PATTERN = re.compile(
    r"(\bOR\b\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+|\bUNION\b\s+\bSELECT\b|--|;\s*DROP\b|'\s*OR\s*')",
    re.IGNORECASE,
)

# tracks per-IP profile-access counts within a sliding window, for IDOR detection
_idor_tracker = defaultdict(list)
IDOR_WINDOW_SECONDS = 5
IDOR_THRESHOLD = 3  # distinct user IDs accessed by same IP within window


def emit_alert(technique_id, technique_name, severity, description, evidence):
    alert = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "mitre_technique_id": technique_id,
        "mitre_technique_name": technique_name,
        "severity": severity,
        "description": description,
        "evidence": evidence,
    }
    os.makedirs(os.path.dirname(ALERTS_LOG), exist_ok=True)
    with open(ALERTS_LOG, "a") as f:
        f.write(json.dumps(alert) + "\n")
    print(f"[ALERT][{severity}] {technique_id} {technique_name} :: {description}")


def check_sqli(entry):
    if entry.get("path") != "/users/search":
        return
    name_param = entry.get("args", {}).get("name", "")
    if SQLI_PATTERN.search(name_param):
        emit_alert(
            "T1190", "Exploit Public-Facing Application (SQLi signature match)",
            "HIGH",
            f"SQL injection payload detected in 'name' parameter: {name_param!r}",
            entry,
        )


def check_idor(entry):
    m = re.match(r"^/users/(\d+)/profile$", entry.get("path", ""))
    if not m:
        return
    ip = entry.get("source_ip", "unknown")
    uid = int(m.group(1))
    now = time.time()
    window = _idor_tracker[ip]
    window.append((now, uid))
    _idor_tracker[ip] = [t for t in window if now - t[0] <= IDOR_WINDOW_SECONDS]
    distinct_ids = {uid for _, uid in _idor_tracker[ip]}
    if len(distinct_ids) >= IDOR_THRESHOLD:
        emit_alert(
            "T1078", "Valid Accounts (IDOR / sequential enumeration)",
            "HIGH",
            f"Source {ip} accessed {len(distinct_ids)} distinct user profiles "
            f"({sorted(distinct_ids)}) within {IDOR_WINDOW_SECONDS}s window",
            entry,
        )
        _idor_tracker[ip] = []  # avoid duplicate alert spam for same burst


def check_jwt_forgery(entry):
    if entry.get("path") != "/account":
        return
    token = entry.get("headers_authorization", "")
    if not token.startswith("Bearer "):
        return
    jwt_token = token.split(" ", 1)[1]
    try:
        header_b64 = jwt_token.split(".")[0]
        import base64
        padded = header_b64 + "=" * (-len(header_b64) % 4)
        header = json.loads(base64.urlsafe_b64decode(padded))
    except Exception:
        return
    if header.get("alg", "").lower() == "none":
        emit_alert(
            "T1550.001", "Use Alternate Authentication Material (unsigned JWT)",
            "CRITICAL",
            "Request presented a JWT with alg=none (unsigned token accepted by app)",
            entry,
        )


RULES = [check_sqli, check_idor, check_jwt_forgery]


def process_line(line):
    line = line.strip()
    if not line:
        return
    try:
        entry = json.loads(line)
    except json.JSONDecodeError:
        return
    for rule in RULES:
        rule(entry)


def run_once():
    if not os.path.exists(ACCESS_LOG):
        print(f"No access log found at {ACCESS_LOG} yet.")
        return
    with open(ACCESS_LOG) as f:
        for line in f:
            process_line(line)


def run_follow():
    print("=== Sentinel Range Detector :: following access log ===")
    with open(ACCESS_LOG) as f:
        f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.2)
                continue
            process_line(line)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--follow", action="store_true")
    args = parser.parse_args()
    if args.follow:
        run_follow()
    else:
        run_once()
