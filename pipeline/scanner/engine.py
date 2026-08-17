import os
import re
import time
import random
import subprocess
import socket
from datetime import datetime
from rich.table import Table
from rich.panel import Panel
from rich import box
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn

import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from aggregator.db import Database
import requests
from scanner.discovery import discover_routes, ffuf_available
from scanner.attack_mapping import attack_id_for

# --- SAST: regex-based static pattern rules (mirrors how Semgrep rules work) ---
SAST_RULES = [
    {
        "id": "py-sql-injection",
        "pattern": re.compile(r'execute\s*\(\s*query\s*\)|query\s*=\s*[\"\'].*SELECT.*%s'),
        "title": "Possible SQL Injection (string formatting in query)",
        "severity": "critical",
        "cwe": "CWE-89", "owasp": "A03:2021"
    },
    {
        "id": "py-sql-injection-fstring",
        "pattern": re.compile(r'(execute)\s*\(\s*f[\"\'].*\{.*\}.*[\"\']'),
        "title": "Possible SQL Injection (f-string in query)",
        "severity": "critical",
        "cwe": "CWE-89", "owasp": "A03:2021"
    },
    {
        "id": "py-eval-usage",
        "pattern": re.compile(r'\beval\s*\('),
        "title": "Use of eval() — potential code injection",
        "severity": "high",
        "cwe": "CWE-95", "owasp": "A03:2021"
    },
    {
        "id": "py-os-system",
        "pattern": re.compile(r'os\.system\s*\('),
        "title": "Use of os.system() — potential command injection",
        "severity": "high",
        "cwe": "CWE-78", "owasp": "A03:2021"
    },
    {
        "id": "py-pickle-load",
        "pattern": re.compile(r'pickle\.loads?\s*\('),
        "title": "Insecure deserialization via pickle",
        "severity": "high",
        "cwe": "CWE-502", "owasp": "A08:2021"
    },
    {
        "id": "py-weak-hash",
        "pattern": re.compile(r'hashlib\.(md5|sha1)\s*\('),
        "title": "Use of weak hash algorithm (MD5/SHA1)",
        "severity": "medium",
        "cwe": "CWE-327", "owasp": "A02:2021"
    },
    {
        "id": "py-debug-true",
        "pattern": re.compile(r'DEBUG\s*=\s*True'),
        "title": "Debug mode enabled",
        "severity": "low",
        "cwe": "CWE-489", "owasp": "A05:2021"
    },
    {
        "id": "js-innerHTML",
        "pattern": re.compile(r'\.innerHTML\s*='),
        "title": "Possible DOM-based XSS via innerHTML",
        "severity": "high",
        "cwe": "CWE-79", "owasp": "A03:2021"
    },
]

# --- Secrets: regex patterns mimicking truffleHog/gitleaks style detection ---
SECRET_PATTERNS = [
    {"id": "aws-key", "pattern": re.compile(r'AKIA[0-9A-Z]{16}'), "title": "AWS Access Key ID exposed", "severity": "critical", "cwe": "CWE-798"},
    {"id": "generic-secret", "pattern": re.compile(r'(?i)(secret|api[_-]?key|password|token)\s*=\s*[\"\'][A-Za-z0-9+/=_\-]{12,}[\"\']'), "title": "Hardcoded secret/credential", "severity": "critical", "cwe": "CWE-798"},
    {"id": "private-key", "pattern": re.compile(r'-----BEGIN (RSA |EC )?PRIVATE KEY-----'), "title": "Private key committed to repo", "severity": "critical", "cwe": "CWE-321"},
    {"id": "slack-token", "pattern": re.compile(r'xox[baprs]-[0-9A-Za-z-]{10,}'), "title": "Slack token exposed", "severity": "high", "cwe": "CWE-798"},
]

# XSS probe payload — a marker we can check for unescaped reflection
XSS_PROBE = "<sentinel_xss_test_b3f2>"


def _find_free_target(default_port=5050):
    """Check if a target is already listening; otherwise we'll spin up the demo target."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.3)
        return s.connect_ex(('127.0.0.1', default_port)) == 0



class ScanEngine:
    def __init__(self, console):
        self.console = console
        self.db = Database()

    def _scan_sast(self, target, exclude_dirs=None):
        exclude_dirs = set(exclude_dirs or [])
        findings = []
        for root, dirs, files in os.walk(target):
            dirs[:] = [d for d in dirs if d not in ('.git', 'node_modules', '__pycache__', '.venv', 'venv') and d not in exclude_dirs]
            for fname in files:
                if not fname.endswith(('.py', '.js', '.ts', '.jsx', '.tsx')):
                    continue
                fpath = os.path.join(root, fname)
                try:
                    with open(fpath, 'r', errors='ignore') as f:
                        lines = f.readlines()
                    for i, line in enumerate(lines, 1):
                        # Skip findings explicitly suppressed via a `sentinel-ignore` comment
                        # on this line or the line directly above it (matches real-world
                        # SAST suppression patterns like `# nosec` or `// nosemgrep`).
                        context = line + (lines[i - 2] if i >= 2 else '')
                        if 'sentinel-ignore' in context:
                            continue
                        for rule in SAST_RULES:
                            if rule['pattern'].search(line):
                                findings.append({
                                    "title": rule['title'],
                                    "scan_type": "SAST",
                                    "severity": rule['severity'],
                                    "location": os.path.relpath(fpath, target),
                                    "line_number": i,
                                    "cwe": rule['cwe'],
                                    "owasp": rule['owasp'],
                                    "description": f"Matched rule `{rule['id']}` at line {i}.",
                                })
                except Exception:
                    continue
        return findings

    def _scan_secrets(self, target, exclude_dirs=None):
        exclude_dirs = set(exclude_dirs or [])
        findings = []
        for root, dirs, files in os.walk(target):
            dirs[:] = [d for d in dirs if d not in ('.git', 'node_modules', '__pycache__', '.venv', 'venv') and d not in exclude_dirs]
            for fname in files:
                if fname.endswith(('.db', '.png', '.jpg', '.pdf', '.zip')):
                    continue
                fpath = os.path.join(root, fname)
                try:
                    with open(fpath, 'r', errors='ignore') as f:
                        content = f.read()
                    for rule in SECRET_PATTERNS:
                        for m in rule['pattern'].finditer(content):
                            line_no = content[:m.start()].count('\n') + 1
                            findings.append({
                                "title": rule['title'],
                                "scan_type": "secrets",
                                "severity": rule['severity'],
                                "location": os.path.relpath(fpath, target),
                                "line_number": line_no,
                                "cwe": rule['cwe'],
                                "owasp": "A02:2021",
                                "description": f"Matched secret pattern `{rule['id']}`.",
                            })
                except Exception:
                    continue
        return findings

    def _scan_dast(self, target_url=None, auto_launch=True):
        """
        Real dynamic application security testing: sends live HTTP requests
        against a running target and inspects actual responses. Mirrors what
        OWASP ZAP's baseline scan does, simplified to a focused rule set.
        """
        findings = []
        launched_process = None
        base_url = target_url

        try:
            if base_url is None:
                # No URL given — spin up the bundled demo vulnerable Flask app
                already_running = _find_free_target(5050)
                base_url = "http://127.0.0.1:5050"
                if not already_running and auto_launch:
                    server_path = os.path.join(os.path.dirname(__file__), '..', 'dast_target', 'vulnerable_server.py')
                    launched_process = subprocess.Popen(
                        [sys.executable, server_path],
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
                    )
                    # wait for it to come up
                    for _ in range(30):
                        if _find_free_target(5050):
                            break
                        time.sleep(0.2)

            findings += self._check_headers(base_url, "/")
            findings += self._check_cookies(base_url, "/login")
            findings += self._check_reflected_xss(base_url, "/search", "q")
            findings += self._check_idor(base_url, "/api/users/")
            findings += self._check_open_redirect(base_url, "/redirect", "next")

            # Route discovery (ffuf if installed, else built-in fallback) —
            # surfaces routes beyond the fixed check list above so they're
            # visible in the report even if we don't have a specific test for them.
            discovered = discover_routes(base_url)
            known_paths = {"/", "/login", "/search", "/redirect"}
            for d in discovered:
                if d['path'] in known_paths or d['path'].startswith('/api/users'):
                    continue
                findings.append({
                    "title": f"Discovered endpoint via fuzzing: {d['path']} (HTTP {d['status']})",
                    "scan_type": "DAST", "severity": "low",
                    "location": d['path'], "line_number": None,
                    "cwe": "", "owasp": "",
                    "description": f"Found via {d['tool']} content discovery; not yet covered by a targeted check. Response length {d['length']} bytes.",
                })

        except requests.exceptions.ConnectionError:
            findings.append({
                "title": f"DAST target unreachable: {base_url}",
                "scan_type": "DAST", "severity": "low", "location": base_url,
                "line_number": None, "cwe": "", "owasp": "",
                "description": "Could not establish a connection to the scan target. Skipped live checks.",
            })
        finally:
            if launched_process:
                launched_process.terminate()
                try:
                    launched_process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    launched_process.kill()

        return findings

    def _check_headers(self, base_url, path):
        findings = []
        r = requests.get(base_url + path, timeout=5)
        headers = {k.lower(): v for k, v in r.headers.items()}

        if 'content-security-policy' not in headers:
            findings.append({
                "title": "Missing Content-Security-Policy header", "scan_type": "DAST",
                "severity": "medium", "location": path, "line_number": None,
                "cwe": "CWE-693", "owasp": "A05:2021",
                "description": f"Live response from {base_url}{path} had no CSP header.",
            })
        if 'x-frame-options' not in headers:
            findings.append({
                "title": "X-Frame-Options header not set (clickjacking risk)", "scan_type": "DAST",
                "severity": "medium", "location": path, "line_number": None,
                "cwe": "CWE-1021", "owasp": "A05:2021",
                "description": f"Live response from {base_url}{path} is missing X-Frame-Options.",
            })
        if 'strict-transport-security' not in headers:
            findings.append({
                "title": "Missing Strict-Transport-Security (HSTS) header", "scan_type": "DAST",
                "severity": "low", "location": path, "line_number": None,
                "cwe": "CWE-319", "owasp": "A02:2021",
                "description": f"Live response from {base_url}{path} did not enforce HSTS.",
            })
        server_header = headers.get('server', '')
        if server_header:
            findings.append({
                "title": f"Server header discloses version info ({server_header})", "scan_type": "DAST",
                "severity": "low", "location": path, "line_number": None,
                "cwe": "CWE-200", "owasp": "A05:2021",
                "description": f"Live Server header leaked: '{server_header}'.",
            })
        return findings

    def _check_cookies(self, base_url, path):
        findings = []
        r = requests.get(base_url + path, timeout=5)
        for cookie in r.cookies:
            issues = []
            if not cookie.secure:
                issues.append("missing Secure flag")
            httponly = cookie._rest.get('HttpOnly', False) if hasattr(cookie, '_rest') else False
            if not httponly:
                issues.append("missing HttpOnly flag")
            if issues:
                findings.append({
                    "title": f"Cookie '{cookie.name}' set with weak flags ({', '.join(issues)})",
                    "scan_type": "DAST", "severity": "medium", "location": path, "line_number": None,
                    "cwe": "CWE-614", "owasp": "A05:2021",
                    "description": f"Live cookie inspection on {base_url}{path}: {', '.join(issues)}.",
                })
        return findings

    def _check_reflected_xss(self, base_url, path, param):
        findings = []
        r = requests.get(base_url + path, params={param: XSS_PROBE}, timeout=5)
        if XSS_PROBE in r.text:
            findings.append({
                "title": f"Reflected XSS in '{param}' parameter", "scan_type": "DAST",
                "severity": "high", "location": f"{path}?{param}=<payload>", "line_number": None,
                "cwe": "CWE-79", "owasp": "A03:2021",
                "description": f"Injected probe string was reflected unescaped in the live response from {base_url}{path}.",
            })
        return findings

    def _check_idor(self, base_url, path):
        findings = []
        r1 = requests.get(base_url + path + "1001", timeout=5)
        r2 = requests.get(base_url + path + "9999", timeout=5)
        if r1.status_code == 200 and r2.status_code == 200 and r1.text != r2.text:
            findings.append({
                "title": "Possible IDOR — sequential resource IDs return distinct data without auth check",
                "scan_type": "DAST", "severity": "high", "location": path + "{id}", "line_number": None,
                "cwe": "CWE-639", "owasp": "A01:2021",
                "description": f"Requested {path}1001 and {path}9999 with no auth header; both returned 200 with different user data.",
            })
        return findings

    def _check_open_redirect(self, base_url, path, param):
        findings = []
        evil = "http://evil-attacker-test.example.com"
        r = requests.get(base_url + path, params={param: evil}, allow_redirects=False, timeout=5)
        location = r.headers.get('Location', '')
        if r.status_code in (301, 302, 303, 307, 308) and evil in location:
            findings.append({
                "title": f"Open redirect via '{param}' parameter", "scan_type": "DAST",
                "severity": "medium", "location": f"{path}?{param}=<url>", "line_number": None,
                "cwe": "CWE-601", "owasp": "A01:2021",
                "description": f"Server redirected to attacker-controlled URL unchanged: {location}",
            })
        return findings

    def run(self, target, scan_type, severity_filter, output, save, target_url=None, exclude_dirs=None):
        start = time.time()
        all_findings = []

        progress_console = self.console if output != 'json' else None
        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                       BarColumn(), console=progress_console, transient=(output == 'json'),
                       disable=(output == 'json')) as progress:

            if scan_type in ('sast', 'all'):
                t = progress.add_task("[cyan]Running SAST (static code analysis)...", total=100)
                for i in range(0, 101, 20):
                    progress.update(t, completed=i)
                    time.sleep(0.05)
                all_findings += self._scan_sast(target, exclude_dirs=exclude_dirs)

            if scan_type in ('secrets', 'all'):
                t = progress.add_task("[yellow]Scanning for hardcoded secrets...", total=100)
                for i in range(0, 101, 25):
                    progress.update(t, completed=i)
                    time.sleep(0.04)
                all_findings += self._scan_secrets(target, exclude_dirs=exclude_dirs)

            if scan_type in ('dast', 'all'):
                t = progress.add_task("[magenta]Running DAST (live HTTP scan)...", total=100)
                progress.update(t, completed=30)
                all_findings += self._scan_dast(target_url)
                progress.update(t, completed=100)

        duration = round(time.time() - start, 2)

        if severity_filter != 'all':
            all_findings = [f for f in all_findings if f['severity'] == severity_filter]

        # assign IDs & persist
        for i, f in enumerate(all_findings):
            f['id'] = f"SCAN-{int(time.time())%100000}-{i}"
            f['discovered_at'] = datetime.now().isoformat()
            f['status'] = 'open'
            f['attack_id'] = attack_id_for(f.get('cwe', ''))
            if save:
                self.db.insert_vuln(f)

        if save:
            self.db.log_scan(scan_type, target, all_findings, duration)

        self._render(all_findings, duration, output)
        return all_findings

    def _render(self, findings, duration, output):
        sev_color = {"critical": "bold red", "high": "bold orange3", "medium": "bold yellow", "low": "bold green"}

        if output == 'json':
            import json as j
            self.console.print_json(j.dumps(findings, indent=2))
            return

        if not findings:
            self.console.print(Panel("[bold green]✓ No new findings detected in scanned files.[/bold green]\n"
                                      "[dim]Note: synthetic vulnerable code lives in scanner/test_fixtures/ for demo purposes.[/dim]",
                                      border_style="green"))
            return

        table = Table(box=box.ROUNDED, border_style="cyan", title=f"[bold]Scan Results — {len(findings)} findings in {duration}s[/bold]")
        table.add_column("Severity", justify="center")
        table.add_column("Type")
        table.add_column("Title", max_width=45)
        table.add_column("Location", style="dim", max_width=30)
        table.add_column("CWE", style="dim")
        table.add_column("ATT&CK", style="magenta")

        sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        for f in sorted(findings, key=lambda x: sev_order.get(x['severity'], 4)):
            loc = f['location']
            if f.get('line_number'):
                loc += f":{f['line_number']}"
            table.add_row(
                f"[{sev_color.get(f['severity'],'white')}]{f['severity'].upper()}[/{sev_color.get(f['severity'],'white')}]",
                f['scan_type'], f['title'], loc, f.get('cwe',''), attack_id_for(f.get('cwe',''))
            )
        self.console.print(table)

        counts = {}
        for f in findings:
            counts[f['severity']] = counts.get(f['severity'], 0) + 1
        summary = "  ".join(f"[{sev_color.get(k,'white')}]{k.upper()}: {v}[/{sev_color.get(k,'white')}]" for k, v in counts.items())
        self.console.print(Panel(summary, border_style="dim", title="Summary"))
