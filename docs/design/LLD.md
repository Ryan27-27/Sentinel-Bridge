# Low Level Design (LLD) — Sentinel

## Pipeline Subsystem (`platform/pipeline/`)

### `sentinel.py` — CLI entrypoint (Click)
Commands: `scan`, `vulns`, `triage`, `dashboard`, `discover`, `automate`,
`status`, `demo`. Each command lazily imports its backing module so `--help`
stays fast and modules without their deps installed don't break unrelated
commands.

### `scanner/engine.py` — `ScanEngine`
- `_scan_sast(target, exclude_dirs)` — walks the target tree (skipping
  `.git`, `node_modules`, `__pycache__`, venvs, and caller-supplied
  `--exclude` dirs), regex-matches each `.py/.js/.ts/.jsx/.tsx` line against
  `SAST_RULES` (8 rules: SQLi via string/f-string formatting, `eval()`,
  `os.system()`, `pickle.load`, weak hashes, `DEBUG=True`, DOM XSS via
  `innerHTML`). Honors a `sentinel-ignore` suppression comment on the
  flagged line or the line above it, mirroring `# nosec` / `// nosemgrep`.
- `_scan_secrets(target)` — regex scan for AWS keys, generic
  secret/password/token assignments, PEM private keys, Slack tokens.
- `_scan_dast(target_url, auto_launch)` — auto-launches the bundled
  `dast_target/vulnerable_server.py` on `:5050` if no `--target-url` is
  given, then runs five live checks against it: security headers
  (CSP/X-Frame-Options/HSTS/Server disclosure), cookie flags, reflected XSS
  (injects a marker string, checks for unescaped reflection), IDOR
  (compares two sequential-ID responses for distinct data with no auth
  header), open redirect (`Location` header echoes an attacker URL
  unchanged).
- Every finding carries `cwe` + `owasp` fields, which is what lets
  `scanner/attack_mapping.py` tag it with an ATT&CK technique later.

### `scanner/discovery.py`
`discover_routes(base_url, wordlist)` — uses `ffuf` via subprocess if
installed (`ffuf_available()` checks `shutil.which`), otherwise falls back to
sequential `requests.get` calls against the bundled wordlist. Same
discover-then-test order real DAST tools use.

### `scanner/attack_mapping.py`
Static `CWE_TO_ATTACK` dict (24 entries) mapping CWE IDs to `(ATT&CK ID,
label)` tuples. `attack_id_for(cwe)` returns `""` for anything unmapped —
deliberately conservative, no guessed mappings.

### `aggregator/db.py` — `Database`
SQLite-backed. Two tables: `vulnerabilities` (id, title, scan_type,
severity, location, line_number, status, assigned_to, fixed_at,
description, cwe, owasp, discovered_at, notes) and `scan_runs` (history for
trend reporting). Seeds 16 realistic demo vulnerabilities on first run so
`dashboard`/`vulns` have data with zero setup. Key methods: `insert_vuln`,
`get_vulns` (filterable/sortable), `update_vuln`, `get_stats`,
`get_mttr_by_severity`, `log_scan`, `get_scan_history`.

### `aggregator/triage.py` — `TriageEngine`
`list_vulns()` renders a filtered/sorted table. `triage_vuln(id, action,
assignee, note)` applies assign/close/wontfix/reopen against the DB.

### `automation/pipeline.py` — `AutomationPipeline`
Three-stage `run(dry_run)`:
1. **Dedup** — groups by `(title.lower(), location)`, flags repeats.
2. **Auto-route** — unassigned open vulns matched against `ROUTING_RULES`
   (path-prefix → team, e.g. `src/auth` → backend-team, falls back to
   `security-team`), mirroring CODEOWNERS-style automation.
3. **SLA breach detection** — compares `discovered_at` age against
   `SLA_DAYS` per severity (critical=7, high=14, medium=30, low=90).

### `dashboard/metrics.py` — `MetricsDashboard`
Four report types (`summary`, `mttr`, `trend`, `pipeline`), each a Rich
table/panel: open-vuln bar chart by severity, MTTR vs. SLA target per
severity, last-N-days scan history, and an SSDLC pipeline-health panel
(SAST/DAST/secrets/dependency coverage + CI/CD gate status).

## Range Subsystem (`platform/range/`)

### `vulnerable_app/app.py`
Flask app on `:5060` (deliberately offset from pipeline's `:5050` target so
both can run simultaneously). Three seeded vulnerabilities: SQLi
(`/users/search?name=`, string-concatenated query), IDOR
(`/users/<id>/profile`, no ownership check), broken JWT (`/account`,
accepts `alg=none`). Every request is logged as structured JSON to
`logs/access.jsonl` via `@app.after_request`.

### `attacker/exploit_runner.py`
Automated exploit chain: recon (T1595) → SQLi (T1190) → IDOR enumeration
(T1078) → forged `alg=none` JWT (T1550.001). Each attempt logged to
`logs/attack_log.jsonl` with a UTC timestamp and MITRE technique ID/name —
this timestamp is what `dashboard/report_generator.py` later joins against
detection timestamps to compute MTTD.

### `detector/detection_engine.py`
Tails `logs/access.jsonl` (`--follow` mode uses `readline()` in a poll
loop). Three rules: SQLi regex signature match on the `name` param; IDOR via
a per-IP sliding window (flags ≥3 distinct user IDs within 5s); JWT `alg`
header decode (flags `alg=none` regardless of signature). Alerts written to
`logs/alerts.jsonl`.

### `dashboard/report_generator.py`
Joins `attack_log.jsonl` and `alerts.jsonl` by `mitre_technique_id`,
computes first-attack-time vs. first-alert-time per technique (MTTD),
renders a dark-themed HTML dashboard with detection rate and per-technique
MTTD.

## Bridge (`platform/scripts/unified_report.py`)

Pulls open findings from the pipeline's `Database` (tagging each with
`attack_id_for(cwe)`), pulls range's attack/alert results (preferring live
`range/logs/`, falling back to the checked-in `range/sample_run/` so the
report works with zero setup), and produces one table keyed by ATT&CK
technique ID showing: found pre-release? / detected at runtime? / MTTD /
covered on both sides?
