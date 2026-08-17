"""
discovery.py — route/endpoint discovery for the DAST engine.

Uses ffuf (https://github.com/ffuf/ffuf) if installed on the system to fuzz
for live routes on a target before running vulnerability checks against them.
This mirrors how real DAST pipelines work: spider/discover first, then test
each discovered endpoint.

If ffuf is not installed, falls back to a small built-in wordlist scanned
with plain HTTP requests (slower, no concurrency, but zero extra dependencies
so the rest of the pipeline still works out of the box).
"""

import os
import json
import shutil
import subprocess
import tempfile

import requests

WORDLIST_PATH = os.path.join(os.path.dirname(__file__), '..', 'scripts', 'wordlists', 'common.txt')


def ffuf_available():
    return shutil.which('ffuf') is not None


def discover_routes(base_url, wordlist=WORDLIST_PATH, timeout=20):
    """
    Returns a list of dicts: [{"path": "/login", "status": 200, "length": 103}, ...]
    Uses ffuf if available, otherwise falls back to sequential requests.
    """
    if ffuf_available():
        return _discover_with_ffuf(base_url, wordlist, timeout)
    return _discover_with_requests(base_url, wordlist)


def _discover_with_ffuf(base_url, wordlist, timeout):
    results = []
    with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as tmp:
        out_path = tmp.name

    try:
        target = base_url.rstrip('/') + '/FUZZ'
        cmd = [
            'ffuf',
            '-w', wordlist,
            '-u', target,
            '-mc', '200,201,204,301,302,307,401,403',
            '-of', 'json',
            '-o', out_path,
            '-s',                     # silent
            '-t', '20',                # threads
            '-timeout', '5',
        ]
        subprocess.run(cmd, capture_output=True, timeout=timeout)

        with open(out_path, 'r') as f:
            data = json.load(f)

        for r in data.get('results', []):
            results.append({
                "path": "/" + r['input'].get('FUZZ', ''),
                "status": r['status'],
                "length": r['length'],
                "tool": "ffuf",
            })
    except (subprocess.TimeoutExpired, json.JSONDecodeError, FileNotFoundError, KeyError):
        # Fall back silently if ffuf misbehaves for any reason
        return _discover_with_requests(base_url, wordlist)
    finally:
        if os.path.exists(out_path):
            os.remove(out_path)

    return results


def _discover_with_requests(base_url, wordlist):
    results = []
    try:
        with open(wordlist, 'r') as f:
            words = [w.strip() for w in f if w.strip() and not w.startswith('#')]
    except FileNotFoundError:
        return results

    for word in words:
        url = base_url.rstrip('/') + '/' + word
        try:
            r = requests.get(url, timeout=3, allow_redirects=False)
            if r.status_code in (200, 201, 204, 301, 302, 307, 401, 403):
                results.append({
                    "path": "/" + word,
                    "status": r.status_code,
                    "length": len(r.content),
                    "tool": "requests-fallback",
                })
        except requests.exceptions.RequestException:
            continue

    return results
