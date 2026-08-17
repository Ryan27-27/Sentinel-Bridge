# Sentinel Range — Purple Team Attack-Detection Lab

A self-contained lab that demonstrates both sides of application security in one system:
a deliberately vulnerable API (red team target), an automated exploit chain that attacks it,
and a detection engine (blue team) that has to catch each attack in near real time. All
attacks and detections are mapped to **MITRE ATT&CK** technique IDs, and a dashboard reports
**Mean Time To Detect (MTTD)** per technique.

> ⚠️ Lab-only. The target app intentionally contains real vulnerabilities. Do not deploy it
> outside an isolated environment.

## Why this project

Most security portfolios show *either* offensive skills (CTF writeups, pentest labs) *or*
defensive skills (SIEM setups, log analysis) in isolation. This project ties them together:
the same three vulnerability classes are both exploited and detected, so it demonstrates the
full loop — vulnerable code → exploitation → signature/heuristic detection → measured
response time — the way an AppSec or Security Engineer role actually operates day to day.

## Architecture

```
sentinel-range/
├── vulnerable_app/       # Flask API with 3 seeded vulnerabilities
│   └── app.py
├── attacker/              # Automated exploit chain (red team)
│   └── exploit_runner.py
├── detector/              # Log-based detection engine (blue team)
│   └── detection_engine.py
├── dashboard/             # MTTD report generator
│   └── report_generator.py
├── logs/                  # Shared structured logs (access, attacks, alerts)
├── docker-compose.yml
└── requirements.txt
```

## Seeded vulnerabilities & corresponding detections

| # | Vulnerability | Endpoint | MITRE ATT&CK | Detection rule |
|---|---|---|---|---|
| 1 | SQL Injection (string-concatenated query) | `GET /users/search?name=` | T1190 – Exploit Public-Facing Application | Regex signature match on SQL meta-characters/keywords in request params |
| 2 | IDOR (no ownership check on resource access) | `GET /users/<id>/profile` | T1078 – Valid Accounts | Sliding-window tracker flags an IP accessing ≥3 distinct user IDs within 5s |
| 3 | Broken JWT verification (accepts `alg=none`) | `GET /account` | T1550.001 – Use Alternate Authentication Material | Decodes JWT header and flags unsigned (`alg=none`) tokens |

Recon-style traffic (`T1595 – Active Scanning`) is also logged by the attacker for realism,
but intentionally has no matching detection rule — plain GET requests to public endpoints are
indistinguishable from normal traffic, which is an accurate (and honest) limitation to call out.

## Running it

### Locally (no Docker)
```bash
pip install -r requirements.txt

# terminal 1
python3 vulnerable_app/app.py

# terminal 2
python3 detector/detection_engine.py --follow

# terminal 3
python3 attacker/exploit_runner.py

# after the attack chain finishes
python3 dashboard/report_generator.py
open dashboard/dashboard.html
```

### With Docker
```bash
docker compose up --build -d
python3 attacker/exploit_runner.py   # run from host, targeting localhost:5060
python3 dashboard/report_generator.py
```

## Sample result

A full attack chain (recon + SQLi + IDOR + JWT forgery) against the current rule set achieves:
- **Detection rate:** 3 of 4 attack techniques (75%)
- **Average MTTD:** sub-second (rule-based detection runs on log tail, effectively real-time)

## Possible extensions
- Replace regex-based SQLi detection with a WAF-style ModSecurity CRS ruleset
- Add rate-limiting as an active response once an alert fires (not just detection)
- Ship logs to a real SIEM (ELK/Wazuh) instead of the custom detector
- Add a 4th vulnerability class (SSRF or path traversal) to broaden ATT&CK coverage
