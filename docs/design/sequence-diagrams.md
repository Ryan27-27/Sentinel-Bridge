# Sequence Diagrams — Sentinel

## 1. CI/CD scan (GitHub Actions, on every push/PR)

```
Developer          GitHub Actions        sentinel.py           Database        Trivy
   │  git push          │                     │                    │             │
   ├───────────────────►│                     │                    │             │
   │                    │  sentinel scan . --type sast --exclude test_fixtures   │
   │                    ├────────────────────►│                    │             │
   │                    │                     │  SAST + secrets scan            │
   │                    │                     │  (walks tree, regex rules)      │
   │                    │                     ├───────────────────►│ INSERT      │
   │                    │  scan-results.json  │                    │             │
   │                    │◄────────────────────┤                    │             │
   │                    │  sentinel scan --type dast (bundled target)           │
   │                    ├────────────────────►│  live HTTP checks  │             │
   │                    │  dast-results.json  │◄──────┐            │             │
   │                    │◄────────────────────┤       │            │             │
   │                    │  [gate] any critical finding? ──► fail build          │
   │                    │  docker build && trivy image scan                     │
   │                    ├───────────────────────────────────────────────────────►│
   │                    │  image CVE report   │                    │             │
   │                    │◄──────────────────────────────────────────────────────┤
   │                    │  sentinel automate (dedup/route/SLA)                  │
   │                    ├────────────────────►│                    │             │
   │                    │  upload dashboard report as build artifact            │
   │                    │                     │                    │             │
```

## 2. Purple-team attack/detection loop (Range)

```
exploit_runner.py       vulnerable_app.py (:5060)      access.jsonl      detection_engine.py     alerts.jsonl
      │  GET /users/search?name=' OR '1'='1        │                        │                       │
      ├──────────────────────────────────────────►│                        │                       │
      │                                     query executes,                │                       │
      │                                     row returned (200)              │                       │
      │  log_attack(T1190, ts=t0) ──► attack_log.jsonl                     │                       │
      │                                             │  after_request:       │                       │
      │                                             │  append access.jsonl  │                       │
      │                                             ├───────────────────────►                       │
      │                                             │                        │  tail (poll loop)     │
      │                                             │                        │  regex match on       │
      │                                             │                        │  'name' param          │
      │                                             │                        │  emit_alert(T1190,     │
      │                                             │                        │    ts=t1) ─────────────►
      │                                             │                        │                       │
      │              (same pattern repeats for IDOR / forged-JWT attacks)                            │
      │                                                                                                │
report_generator.py: join attack_log(t0) + alerts(t1) by technique ─► MTTD = t1 - t0
```

## 3. Unified ATT&CK coverage report

```
unified_report.py        aggregator/db.py         attack_mapping.py       range/logs (or sample_run/)
      │  get_vulns(status='open')      │                    │                        │
      ├───────────────────────────────►│                    │                        │
      │  open vulnerability rows       │                    │                        │
      │◄───────────────────────────────┤                    │                        │
      │  attack_id_for(cwe) for each row│                    │                        │
      ├────────────────────────────────────────────────────►│                        │
      │  ATT&CK technique ID (or '' if unmapped)             │                        │
      │◄────────────────────────────────────────────────────┤                        │
      │  load attack_log.jsonl + alerts.jsonl (live, else sample_run/ fallback)       │
      ├──────────────────────────────────────────────────────────────────────────────►
      │  per-technique: first_attack_ts, first_alert_ts, alert_count                  │
      │◄──────────────────────────────────────────────────────────────────────────────
      │  merge on technique ID → rows: pipeline_found? / range_status / mttd / both   │
      │  render unified_dashboard.html                                                │
```
