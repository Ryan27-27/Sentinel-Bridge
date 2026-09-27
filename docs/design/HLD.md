# High Level Design (HLD) — Sentinel

## System Purpose

Sentinel answers two connected questions about application security:

1. **Pipeline** — "Before this code ships, what vulnerabilities does it contain?"
2. **Range** — "If someone actually exploits one of those vulnerability classes at runtime, do we detect it — and how fast?"

Most AppSec tooling only answers the first question. Sentinel ties both together on a single axis — the **MITRE ATT&CK technique ID** — so a static finding and a live detection can be cross-referenced instead of living in two disconnected dashboards.

## Subsystems

```
┌─────────────────────────────┐        ┌──────────────────────────────┐
│   Pipeline (pre-release)    │        │   Range (runtime, purple team) │
│                              │        │                                │
│  SAST + DAST + Secrets scan │        │  Vulnerable target (Flask)    │
│         │                   │        │         │                      │
│         ▼                   │        │         ▼                      │
│  Aggregator (SQLite)         │        │  Red-team exploit chain       │
│         │                   │        │  (MITRE ATT&CK-mapped)        │
│         ▼                   │        │         │                      │
│  Triage + Automation         │        │         ▼                      │
│  (dedup, routing, SLA)       │        │  Blue-team detection engine   │
│         │                   │        │  (log-based, real-time)       │
│         ▼                   │        │         │                      │
│  Metrics Dashboard (MTTR)    │        │  MTTD / detection-rate report │
└─────────────┬────────────────┘        └───────────────┬────────────────┘
              │                                          │
              └───────────── attack_id_for(CWE) ─────────┘
                       scripts/unified_report.py
                    (Unified ATT&CK Coverage Dashboard)
```

## Deployment Path

```
Developer commits → GitHub Actions (on push/PR + nightly cron)
   → SAST + secrets scan (fails build on critical findings)
   → DAST scan against bundled/live target
   → Docker image build → Trivy image scan
   → Automation pipeline (dedup, auto-route, SLA check)
   → Metrics report uploaded as build artifact
   → (optional) Kubernetes: nightly CronJob + long-running Deployment
```

## Key Design Decisions

- **Pure Python core** (Click + Rich + Flask + requests) — no platform-specific
  code, runs identically on Windows/Linux/macOS.
- **SQLite over a managed DB** — zero-ops persistence appropriate for a
  single-team tool; the schema (`aggregator/db.py`) is relational and would
  port to Postgres without changes if scaled.
- **Regex/pattern-based SAST**, deliberately scoped to mirror how a real
  Semgrep rule works, not a full AST analyzer — the point is demonstrating
  the pipeline architecture, not reimplementing Semgrep.
- **Real, live DAST** — the DAST engine sends actual HTTP requests against a
  running target (bundled demo app or any `--target-url`) rather than
  simulating results.
- **ffuf with automatic fallback** — uses the real industry-standard fuzzer
  when present, degrades gracefully to a built-in scanner so the tool works
  with zero required external dependencies.
- **CWE → ATT&CK mapping is conservative** (`scanner/attack_mapping.py`) —
  unmapped CWEs return `None` rather than a guessed technique, so the unified
  report never fabricates a correspondence.
