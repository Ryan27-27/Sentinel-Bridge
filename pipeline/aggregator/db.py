import sqlite3
import os
import json
from datetime import datetime, timedelta
import random

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'sentinel.db')

SEED_VULNS = [
    ("SQL Injection in login endpoint", "SAST", "critical", "src/auth/login.py", 42, "open", "backend-team", None,
     "User input directly concatenated into SQL query without parameterization. Attacker can bypass auth or dump DB.",
     "CWE-89", "A03:2021", -20),
    ("Hardcoded AWS Secret Key", "secrets", "critical", "config/settings.py", 7, "open", None, None,
     "AWS_SECRET_KEY found in plaintext. Immediate revocation and rotation required.",
     "CWE-798", "A02:2021", -5),
    ("Reflected XSS in search param", "DAST", "high", "/api/search?q=<input>", None, "open", "frontend-team", None,
     "Search parameter reflected in response without encoding. Can be used for session hijacking.",
     "CWE-79", "A03:2021", -15),
    ("Insecure Direct Object Reference", "DAST", "high", "/api/users/{id}/profile", None, "open", None, None,
     "Authenticated users can access other users' profiles by changing the ID parameter.",
     "CWE-639", "A01:2021", -10),
    ("JWT Algorithm Confusion (none alg)", "SAST", "high", "src/middleware/auth.py", 88, "open", "backend-team", None,
     "JWT library accepts 'none' algorithm, allowing unsigned tokens to pass verification.",
     "CWE-347", "A02:2021", -8),
    ("Path Traversal in file download", "SAST", "high", "src/files/download.py", 23, "fixed", "backend-team", None,
     "Filename parameter not sanitized, allows reading arbitrary files from server filesystem.",
     "CWE-22", "A01:2021", -30),
    ("Missing HTTPS enforcement", "DAST", "medium", "/", None, "open", "devops-team", None,
     "Application does not redirect HTTP to HTTPS, allowing cleartext transmission of credentials.",
     "CWE-319", "A02:2021", -3),
    ("Verbose error messages exposing stack trace", "DAST", "medium", "/api/*", None, "fixed", "backend-team", None,
     "Stack traces with internal paths and library versions returned in error responses.",
     "CWE-209", "A05:2021", -25),
    ("Dependency: lodash 4.17.4 (prototype pollution)", "SAST", "medium", "package.json", 12, "open", "frontend-team", None,
     "Outdated lodash version vulnerable to prototype pollution attacks (CVE-2019-10744).",
     "CWE-1321", "A06:2021", -12),
    ("SSRF via webhook URL parameter", "DAST", "high", "/api/webhooks/register", None, "open", None, None,
     "Webhook URL not validated against allowlist, enabling SSRF to internal metadata services.",
     "CWE-918", "A10:2021", -7),
    ("Insecure cookie flags (missing HttpOnly)", "DAST", "medium", "/", None, "fixed", "frontend-team", None,
     "Session cookies set without HttpOnly flag, accessible via JavaScript.",
     "CWE-1004", "A05:2021", -18),
    ("Rate limiting absent on login endpoint", "DAST", "medium", "/api/auth/login", None, "open", "backend-team", None,
     "No brute force protection on authentication endpoint.",
     "CWE-307", "A07:2021", -6),
    ("NoSQL Injection in MongoDB query", "SAST", "high", "src/api/products.py", 67, "open", None, None,
     "User-controlled input passed directly to MongoDB find() without sanitization.",
     "CWE-943", "A03:2021", -4),
    ("Debug mode enabled in production", "SAST", "low", "config/prod.yaml", 3, "fixed", "devops-team", None,
     "DEBUG=True found in production configuration, exposing sensitive information.",
     "CWE-489", "A05:2021", -22),
    ("Unvalidated redirect after login", "DAST", "low", "/api/auth/callback", None, "open", "backend-team", None,
     "next= parameter not validated, allowing open redirect to phishing sites.",
     "CWE-601", "A01:2021", -9),
    ("Dependency: requests 2.18.0 (outdated)", "SAST", "low", "requirements.txt", 5, "open", None, None,
     "Outdated requests library, multiple CVEs in versions < 2.31.0.",
     "CWE-1035", "A06:2021", -2),
]

class Database:
    def __init__(self):
        self.db_path = DB_PATH
        self._init_db()

    def _connect(self):
        return sqlite3.connect(self.db_path)

    def _init_db(self):
        conn = self._connect()
        c = conn.cursor()
        c.execute('''
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                scan_type TEXT,
                severity TEXT,
                location TEXT,
                line_number INTEGER,
                status TEXT DEFAULT 'open',
                assigned_to TEXT,
                fixed_at TEXT,
                description TEXT,
                cwe TEXT,
                owasp TEXT,
                discovered_at TEXT,
                notes TEXT
            )
        ''')
        c.execute('''
            CREATE TABLE IF NOT EXISTS scan_runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_at TEXT,
                scan_type TEXT,
                target TEXT,
                total_found INTEGER,
                critical INTEGER,
                high INTEGER,
                medium INTEGER,
                low INTEGER,
                duration_sec REAL
            )
        ''')
        conn.commit()

        # Seed if empty
        c.execute("SELECT COUNT(*) FROM vulnerabilities")
        if c.fetchone()[0] == 0:
            self._seed(c)
            conn.commit()
        conn.close()

    def _seed(self, c):
        now = datetime.now()
        for i, v in enumerate(SEED_VULNS):
            title, scan_type, severity, location, line_num, status, assignee, fixed_at, desc, cwe, owasp, days_ago = v
            vid = f"SENT-{1000 + i + 1}"
            discovered = (now + timedelta(days=days_ago)).isoformat()
            fa = (now + timedelta(days=days_ago + random.randint(2, 8))).isoformat() if status == 'fixed' else None
            c.execute(
                "INSERT OR IGNORE INTO vulnerabilities VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (vid, title, scan_type, severity, location, line_num, status, assignee, fa, desc, cwe, owasp, discovered, None)
            )

    def insert_vuln(self, vuln: dict):
        conn = self._connect()
        c = conn.cursor()
        c.execute(
            "INSERT OR IGNORE INTO vulnerabilities VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (vuln['id'], vuln['title'], vuln['scan_type'], vuln['severity'],
             vuln['location'], vuln.get('line_number'), vuln.get('status','open'),
             vuln.get('assigned_to'), vuln.get('fixed_at'),
             vuln.get('description',''), vuln.get('cwe',''), vuln.get('owasp',''),
             vuln.get('discovered_at', datetime.now().isoformat()), vuln.get('notes'))
        )
        conn.commit()
        conn.close()

    def get_vulns(self, severity='all', status='all', limit=50, sort='severity'):
        conn = self._connect()
        c = conn.cursor()
        severity_order = "CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END"
        sort_clause = severity_order if sort == 'severity' else 'discovered_at DESC'

        query = "SELECT * FROM vulnerabilities WHERE 1=1"
        params = []
        if severity != 'all':
            query += " AND severity=?"
            params.append(severity)
        if status != 'all':
            query += " AND status=?"
            params.append(status)
        # sort_clause is selected from a fixed internal allowlist (see severity_order above),
        # never from raw user input, so this f-string is not attacker-controllable. sentinel-ignore: CWE-89
        query += f" ORDER BY {sort_clause} LIMIT ?"
        params.append(limit)

        c.execute(query, params)
        rows = c.fetchall()
        conn.close()
        cols = ['id','title','scan_type','severity','location','line_number','status','assigned_to','fixed_at','description','cwe','owasp','discovered_at','notes']
        return [dict(zip(cols, r)) for r in rows]

    def update_vuln(self, vuln_id, **kwargs):
        conn = self._connect()
        c = conn.cursor()
        sets = ', '.join(f"{k}=?" for k in kwargs)
        vals = list(kwargs.values()) + [vuln_id]
        # column names in `sets` come from internal kwargs (triage actions), not user HTTP input;
        # values themselves are still parameterized via `?`. sentinel-ignore: CWE-89
        c.execute(f"UPDATE vulnerabilities SET {sets} WHERE id=?", vals)
        conn.commit()
        affected = c.rowcount
        conn.close()
        return affected > 0

    def get_vuln(self, vuln_id):
        conn = self._connect()
        c = conn.cursor()
        c.execute("SELECT * FROM vulnerabilities WHERE id=?", (vuln_id,))
        row = c.fetchone()
        conn.close()
        if not row:
            return None
        cols = ['id','title','scan_type','severity','location','line_number','status','assigned_to','fixed_at','description','cwe','owasp','discovered_at','notes']
        return dict(zip(cols, row))

    def get_stats(self):
        conn = self._connect()
        c = conn.cursor()
        c.execute("SELECT severity, COUNT(*) FROM vulnerabilities WHERE status='open' GROUP BY severity")
        rows = dict(c.fetchall())
        c.execute("SELECT COUNT(*) FROM vulnerabilities WHERE status='fixed'")
        fixed = c.fetchone()[0]
        c.execute("SELECT COUNT(*) FROM vulnerabilities")
        total = c.fetchone()[0]
        conn.close()
        return {
            'critical': rows.get('critical', 0),
            'high': rows.get('high', 0),
            'medium': rows.get('medium', 0),
            'low': rows.get('low', 0),
            'fixed': fixed,
            'total': total,
        }

    def log_scan(self, scan_type, target, results, duration):
        conn = self._connect()
        c = conn.cursor()
        by_sev = {}
        for v in results:
            by_sev[v['severity']] = by_sev.get(v['severity'], 0) + 1
        c.execute(
            "INSERT INTO scan_runs (run_at,scan_type,target,total_found,critical,high,medium,low,duration_sec) VALUES (?,?,?,?,?,?,?,?,?)",
            (datetime.now().isoformat(), scan_type, target, len(results),
             by_sev.get('critical',0), by_sev.get('high',0),
             by_sev.get('medium',0), by_sev.get('low',0), duration)
        )
        conn.commit()
        conn.close()

    def get_scan_history(self, days=30):
        conn = self._connect()
        c = conn.cursor()
        since = (datetime.now() - timedelta(days=days)).isoformat()
        c.execute("SELECT * FROM scan_runs WHERE run_at >= ? ORDER BY run_at DESC", (since,))
        rows = c.fetchall()
        conn.close()
        cols = ['id','run_at','scan_type','target','total_found','critical','high','medium','low','duration_sec']
        return [dict(zip(cols, r)) for r in rows]

    def get_mttr_by_severity(self):
        conn = self._connect()
        c = conn.cursor()
        c.execute("SELECT severity, discovered_at, fixed_at FROM vulnerabilities WHERE status='fixed' AND fixed_at IS NOT NULL")
        rows = c.fetchall()
        conn.close()
        mttr = {}
        for sev, disc, fixed in rows:
            try:
                d = datetime.fromisoformat(disc)
                f = datetime.fromisoformat(fixed)
                days = (f - d).days
                if sev not in mttr:
                    mttr[sev] = []
                mttr[sev].append(days)
            except:
                pass
        return {k: round(sum(v)/len(v), 1) for k, v in mttr.items() if v}
