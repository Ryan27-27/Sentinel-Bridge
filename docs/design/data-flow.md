# Data Flow — Sentinel

## Pipeline: scan → triage → automate → report

```
Source code / live target
        │
        ▼
scanner/engine.py  ──►  SAST findings  (file, line, CWE, OWASP category)
        │           ──►  DAST findings  (live HTTP response evidence)
        │           ──►  Secrets findings (pattern match, file, line)
        ▼
aggregator/db.py   ──►  INSERT INTO vulnerabilities (SQLite)
        │                each row: id, title, severity, location,
        │                cwe, owasp, discovered_at, status='open'
        ▼
automation/pipeline.py
   1. dedup:      group by (title, location) → flag repeats
   2. auto-route: location prefix → ROUTING_RULES → assigned_to
   3. SLA check:  age(discovered_at) vs SLA_DAYS[severity] → breach list
        ▼
dashboard/metrics.py  ──►  severity bar chart, MTTR vs SLA, scan-history
                            trend, SSDLC pipeline-health panel
```

## Range: attack → detect → measure

```
attacker/exploit_runner.py
        │  sends live HTTP requests (recon, SQLi, IDOR, forged JWT)
        ▼
vulnerable_app/app.py (Flask, :5060)
        │  every request logged as structured JSON
        ▼
logs/access.jsonl
        │  tailed continuously
        ▼
detector/detection_engine.py
        │  regex / sliding-window / JWT-header rules
        ▼
logs/alerts.jsonl  (each alert: mitre_technique_id, severity, timestamp)

Meanwhile, in parallel:
attacker/exploit_runner.py  ──►  logs/attack_log.jsonl
                                  (mitre_technique_id, timestamp)

dashboard/report_generator.py
   joins attack_log.jsonl ⨝ alerts.jsonl  ON mitre_technique_id
   MTTD = first_alert_timestamp - first_attack_timestamp
        ▼
   dashboard.html  (detection rate %, per-technique MTTD)
```

## Unified Coverage: joining both halves

```
pipeline: aggregator/db.py            range: logs/attack_log.jsonl +
   open vulnerabilities                      logs/alerts.jsonl
   (cwe field per row)                        (mitre_technique_id per row)
        │                                          │
        ▼                                          ▼
scanner/attack_mapping.py                  (already ATT&CK-native)
   attack_id_for(cwe) → ATT&CK ID
        │                                          │
        └──────────────────┬───────────────────────┘
                            ▼
              scripts/unified_report.py
   for each ATT&CK technique ID seen on either side:
     - found_pre_release  = pipeline flagged this CWE class?
     - detected_at_runtime = range's detector caught a live exploit?
     - mttd                = range's measured detection speed
     - covered_both_sides  = both true
                            ▼
              unified_dashboard.html
   (falls back to range/sample_run/*.jsonl if range/logs/ is empty,
    so the report renders even before you've run a live attack chain)
```
