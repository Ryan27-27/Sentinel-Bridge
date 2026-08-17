# Sentinel — A Purple Team AppSec Platform

One platform, two loops, the same vocabulary: **find vulnerabilities before ship, and prove you can
both exploit and detect them at runtime.** Built to demonstrate the full skill set a Security
Engineer / AppSec Engineer / purple-team role actually needs — not a red-team CTF writeup on its
own, not a defensive SIEM dashboard on its own, but both sides of the same coin, cross-referenced
against MITRE ATT&CK.

> ⚠️ Lab project. Both halves contain deliberately vulnerable applications for demonstration.
> Run in an isolated environment only.

## Why this exists

Most portfolios show offense *or* defense. Companies hiring for security engineering — including
product-security teams at SaaS companies like Rippling — want someone who can sit in the SSDLC
(shift-left scanning, triage, CI/CD gates) **and** reason like an attacker when validating that
defenses actually catch something. This repo is structured to make that overlap explicit:

| | Pipeline (`/pipeline`) | Range (`/range`) |
|---|---|---|
| **Question it answers** | "Did we ship a vulnerability?" | "If someone exploits it, do we notice — and how fast?" |
| **Role it demonstrates** | AppSec engineering, SSDLC integration, triage/SLA ops | Red-team execution, detection engineering, incident metrics |
| **Output** | Findings dashboard, MTTR, CI security gate | MITRE ATT&CK coverage, Mean Time To Detect (MTTD) |
| **Framework language** | CWE / OWASP Top 10, now also mapped to ATT&CK IDs | MITRE ATT&CK technique IDs natively |

The two were previously separate repos. The concrete thing tying them together in this version:
`pipeline/scanner/attack_mapping.py` maps every CWE the SAST/DAST scanner finds to a MITRE ATT&CK
technique ID (e.g. `CWE-89` SQL injection → `T1190`), so a static/dynamic finding from the pipeline
and a live detection from the range report on the **same coverage matrix** instead of two
disconnected dashboards. That's the "changes required" part of combining these — see below.

## Architecture

![Sentinel platform architecture](docs/architecture.svg)

```
sentinel-platform/
├── pipeline/     AppSec Pipeline Sentinel — SAST/DAST/secrets scanning, triage, SLA/MTTR,
│                 CI/CD security gate, Kubernetes deploy. CLI: `python3 sentinel.py`
│                 → findings now carry an `attack_id` (ATT&CK technique) alongside CWE/OWASP
└── range/        Sentinel Range — vulnerable Flask target + automated exploit chain (red) +
                  log-based detection engine (blue) + MTTD dashboard, natively ATT&CK-mapped
```

## Quick start

**Pipeline** (scan → triage → dashboard → automate):
```bash
cd pipeline
python3 -m venv venv && source venv/bin/activate      # PEP 668 environments (Ubuntu 23.04+/Debian 12+)
pip install -r requirements.txt
python3 sentinel.py demo
```

**Range** (attack → detect → MTTD report):
```bash
cd range
pip install -r requirements.txt
python3 vulnerable_app/app.py            # terminal 1 — runs on :5060
python3 detector/detection_engine.py --follow   # terminal 2
python3 attacker/exploit_runner.py       # terminal 3
python3 dashboard/report_generator.py && open dashboard/dashboard.html
```

Both can run at the same time without a port clash — `range`'s demo target was moved to `:5060`
(from `:5050`) specifically because `pipeline`'s own bundled DAST target already uses `:5050`.
That's the other concrete integration fix: these were built as two independent repos and would
have collided if you tried to demo both live in one sitting.

Each subproject keeps its own detailed README (`pipeline/README.md`, `range/README.md`) for
CI/CD, Docker, and Kubernetes instructions.

**Unified report** (joins both halves on ATT&CK technique ID):
```bash
python3 scripts/unified_report.py
open scripts/unified_dashboard.html
```
Pulls open findings out of `pipeline`'s DB (auto-seeded with demo data on first run) and joins
them against `range`'s attack/detection logs by MITRE ATT&CK ID — one table showing, per
technique, whether it was caught pre-release, whether it was exploited-and-detected at runtime,
and whether it's covered on both sides. Falls back to the checked-in `range/sample_run/` logs if
you haven't run a live attack chain yet, so it works with zero setup.

## What this demonstrates for a purple-team / security engineer role

- **Shift-left AppSec**: SAST/DAST/secrets scanning wired into a CI/CD gate that fails builds on
  critical findings, plus triage workflow and SLA/MTTR tracking — the day-to-day of an AppSec
  engineering team.
- **Adversary simulation**: an automated exploit chain (SQLi, IDOR, JWT `alg=none` forgery, recon)
  run against a real HTTP target, not a theoretical write-up.
- **Detection engineering**: log-based detection rules built to catch exactly those techniques,
  with an honest reporting of what's *not* caught (plain recon traffic) rather than an inflated
  detection rate.
- **Framework fluency**: CWE, OWASP Top 10, and MITRE ATT&CK used consistently and cross-mapped,
  which is how real security teams communicate risk across offense and defense.
- **Platform engineering**: Docker, Kubernetes manifests, GitHub Actions CI/CD, and a TypeScript
  Slack notifier — the deployment and tooling maturity expected of a production security platform,
  not just a script.

## Honest limitations (worth saying out loud in an interview)

- Detection rules are regex/heuristic-based, not a real SIEM (ELK/Wazuh) — called out explicitly
  as a "possible extension" in `range/README.md`.
- `pipeline`'s Docker build and Kubernetes manifests are written to standard patterns but not yet
  verified end-to-end against a live daemon/cluster — noted in `pipeline/README.md`.
- The ATT&CK mapping in `pipeline/scanner/attack_mapping.py` is deliberately conservative: only
  CWEs with a well-established technique correspondence are mapped, unmapped CWEs return an empty
  string rather than a guessed technique.

## Suggested next changes (if you want to keep building this out)

1. Extend `range` with a 4th vulnerability class (SSRF or path traversal) so its ATT&CK coverage
   overlaps more of what `pipeline`'s SAST rules already flag statically.
2. Rename the CLI banners/`author` strings inside `pipeline/sentinel.py` and repo metadata to your
   own name before publishing — the uploaded copy still has a placeholder author.


## System Design

| Document | Description |
|----------|-------------|
| docs/design/HLD.md | High Level Design |
| docs/design/LLD.md | Low Level Design |
| docs/design/sequence-diagrams.md | Sequence diagrams |
| docs/design/data-flow.md | Data flow diagrams |
