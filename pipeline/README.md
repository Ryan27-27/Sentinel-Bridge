# AppSec Pipeline Sentinel

Automated Application Security Monitoring, Triage & Reporting Platform — built to mirror how an
Application Security Engineering team integrates security scanning into the SSDLC.

## What it does

Sentinel plugs into a CI/CD pipeline and:

1. **Scans code** for vulnerabilities using SAST (static pattern rules), DAST (real live HTTP scanning
   against a running target — auto-launches a bundled vulnerable Flask app, or point it at any URL),
   and secrets detection (regex + pattern matching for leaked credentials).
2. **Triages findings** — stores them in a database, lets engineers assign/close/reopen issues, and
   tracks status over time.
3. **Automates routine work** — deduplicates repeated findings, auto-routes vulnerabilities to the
   right team based on file path, and flags anything that has breached its SLA.
4. **Reports on metrics** — a terminal dashboard showing severity breakdowns, MTTR (Mean Time To
   Remediate) against SLA targets, scan history/trends, and pipeline health.
5. **Runs in CI/CD** — a GitHub Actions workflow scans every PR, fails the build on critical findings,
   builds a Docker image, scans that image with Trivy, and uploads a metrics report as an artifact.
6. **Deploys to Kubernetes** — a Deployment + nightly CronJob + PVC for persisting scan history.

## Quick start

```bash
git clone <repo-url>
cd sentinel
```

**Linux/macOS:**
```bash
./setup.sh
```
> On Ubuntu 23.04+/Debian 12+ you'll likely hit `error: externally-managed-environment`. Use a venv:
> ```bash
> python3 -m venv venv
> source venv/bin/activate
> pip install -r requirements.txt
> ```
> Re-activate with `source venv/bin/activate` every time you open a new terminal.

**Windows (PowerShell):**
```powershell
powershell -ExecutionPolicy Bypass -File setup.ps1
```

> **Command name varies by platform.** On Linux/macOS use `python3`. On Windows, `python3` is usually
> just a Microsoft Store stub — use `python` instead. The examples below use `python3`; swap to
> `python` if you're on Windows and get a "Python was not found" error.

```bash
python3 sentinel.py demo                  # full pipeline: scan → triage → dashboard → automate
python3 sentinel.py status                # system health + live vuln stats
python3 sentinel.py scan scanner/test_fixtures --type all   # run a scan
python3 sentinel.py scan --type dast                         # live DAST scan (auto-launches demo target on :5050)
python3 sentinel.py scan --type dast --target-url https://your-app.com   # DAST against any live URL
python3 sentinel.py discover https://your-app.com         # ffuf-based route discovery against a live external URL
python3 sentinel.py vulns --severity critical               # list open critical vulns
python3 sentinel.py triage SENT-1002 assign --assignee devops-team
python3 sentinel.py dashboard --type full                   # metrics dashboard
python3 sentinel.py automate --dry-run                       # dedup / auto-assign / SLA check
```

> **`discover` does not auto-launch the demo target** (only `scan --type dast` does). To run
> `discover http://127.0.0.1:5050`, start the target manually first in a separate terminal:
> ```bash
> python3 dast_target/vulnerable_server.py
> ```

## Run with Docker

> **Note:** the Dockerfile is written correctly and follows standard multi-stage build patterns,
> but `docker build` has not been verified end-to-end (it was built in an environment without a
> Docker daemon available). Test this yourself before relying on it, and report back if the build
> fails.

```bash
docker build -t appsec-sentinel .
docker run --rm appsec-sentinel status
docker run --rm -v $(pwd)/scanner/test_fixtures:/app/target appsec-sentinel scan /app/target --type all
```

## Deploy to Kubernetes

> **Note:** these manifests are valid YAML following standard patterns but have not been tested
> against a real cluster.

```bash
kubectl apply -f k8s/namespace.yaml
kubectl apply -f k8s/cronjob.yaml
kubectl apply -f k8s/deployment.yaml
```

This sets up a nightly CronJob (2 AM) that scans a checked-out repo and persists results to a PVC,
plus a long-running Deployment that runs the automation/triage pipeline.

## CI/CD

See `.github/workflows/sentinel.yml`. On every push/PR:

- Runs the SAST + secrets scan and uploads results as a build artifact
- **Fails the build** if any critical-severity finding is detected (security gate)
- Builds the Docker image and scans it with Trivy for OS/dependency CVEs
- Runs the automation pipeline and uploads a dashboard report

### Excluding paths from the scan / suppressing false positives

`scanner/test_fixtures/` is intentionally vulnerable demo code, so the CI workflow excludes it
from the real-code scan:
```bash
python3 sentinel.py scan . --type sast --exclude test_fixtures
```
`--exclude` is repeatable (`--exclude test_fixtures --exclude legacy`) for multiple directories.

For one-off false positives inside real code (e.g. an f-string building SQL from a fixed
internal allowlist, not user input), add a `sentinel-ignore` comment on the flagged line or the
line above it, with a short justification:
```python
# sort_clause is selected from a fixed internal allowlist, never user input. sentinel-ignore: CWE-89
query += f" ORDER BY {sort_clause} LIMIT ?"
```
The scanner skips any line containing `sentinel-ignore` in itself or the preceding line —
the same pattern real tools use (`# nosec`, `// nosemgrep`).

## Notification layer (TypeScript)

`scripts/notify.ts` reads the JSON scan output and posts a formatted summary to Slack via webhook —
the piece that closes the loop between "a scan found something" and "a human got notified."

```bash
npm install
SLACK_WEBHOOK_URL=https://hooks.slack.com/... npx ts-node scripts/notify.ts scan-results.json
```

## Route discovery (ffuf)

`sentinel discover <url>` fuzzes a target with [ffuf](https://github.com/ffuf/ffuf) — the same
content-discovery approach Burp Suite and OWASP ZAP's spider use — to find live endpoints before
testing them. If `ffuf` isn't installed on the system, it automatically falls back to a slower
built-in scanner using the same wordlist, so the pipeline still works with zero extra setup.

```bash
# Install ffuf (one-time): https://github.com/ffuf/ffuf#installation
go install github.com/ffuf/ffuf/v2@latest

python3 sentinel.py discover https://your-app.vercel.app

# To discover against the bundled local target, start it manually first:
python3 dast_target/vulnerable_server.py &
python3 sentinel.py discover http://127.0.0.1:5050 --wordlist scripts/wordlists/common.txt
```

`scan --type dast` also runs discovery automatically as part of the live scan, surfacing any
endpoints found that aren't already covered by the targeted XSS/IDOR/redirect/cookie checks.

## DAST target app

`dast_target/vulnerable_server.py` is a small intentionally-vulnerable Flask app used purely as a
live scan target. When you run `sentinel scan --type dast` without `--target-url`, the engine
auto-launches this server on `127.0.0.1:5050`, sends real HTTP requests against it (header checks,
an injected XSS probe, IDOR comparison, open redirect test, cookie flag inspection), and tears the
process down afterward. Point `--target-url` at any other live URL to scan that instead.

## Platform compatibility

Pure Python (Click + Rich + requests + Flask) — runs natively on Windows, Linux, and macOS, no
platform-specific code. Use `setup.sh` on Linux/macOS or `setup.ps1` on Windows. `ffuf` ships
binaries for all three platforms; without it, route discovery automatically falls back to a
built-in (slower) scanner so the tool still works out of the box.

## Using a larger wordlist (e.g. SecLists)

The bundled `scripts/wordlists/common.txt` is intentionally small for demo speed. For real use,
swap in a proper wordlist such as [SecLists](https://github.com/danielmiessler/SecLists):

```bash
git clone https://github.com/danielmiessler/SecLists.git
python3 sentinel.py discover https://your-app.com --wordlist SecLists/Discovery/Web-Content/common.txt
```

Or replace the bundled file directly so it becomes the default for every scan:
```bash
cp SecLists/Discovery/Web-Content/common.txt scripts/wordlists/common.txt
```

## Architecture

```
sentinel.py              CLI entrypoint (Click)
scanner/engine.py        SAST + live DAST (real HTTP) + secrets scanning engine
scanner/discovery.py     ffuf-based route discovery (with built-in fallback)
dast_target/              Intentionally vulnerable Flask app used as the DAST scan target
aggregator/db.py         SQLite persistence layer
aggregator/triage.py     Vulnerability listing + triage actions
dashboard/metrics.py     MTTR, severity charts, trend reporting
automation/pipeline.py   Dedup, auto-routing, SLA breach detection
scripts/notify.ts        Slack notification layer (TypeScript)
.github/workflows/       CI/CD pipeline definition
k8s/                     Kubernetes Deployment, CronJob, PVC, ConfigMap
Dockerfile               Container build (non-root user, multi-stage)
```

## Why this exists

Built to demonstrate practical application security engineering: integrating security tooling into
developer workflows, automating the toil around vulnerability triage, and giving a security team
visibility through metrics — rather than just running scanners in isolation.
