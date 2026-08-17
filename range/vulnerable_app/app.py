"""
Sentinel Range - Vulnerable Target Application
------------------------------------------------
A deliberately vulnerable Flask API used as the attack surface for the
purple-team lab. Every request is logged as structured JSON to
logs/access.jsonl so the detection engine can analyze it after the fact.

Seeded vulnerabilities (intentional, for detection-engineering practice only):
  1. SQL Injection      -> /users/search?name=
  2. IDOR                -> /users/<id>/profile
  3. Broken JWT auth     -> /account (accepts alg=none / unsigned tokens)

DO NOT deploy this outside an isolated lab environment.
"""
import json
import os
import sqlite3
import time
from datetime import datetime, timezone

import jwt
from flask import Flask, g, request, jsonify

APP_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(APP_DIR, "app.db")
LOG_PATH = os.path.join(APP_DIR, "..", "logs", "access.jsonl")
JWT_SECRET = "sentinel-lab-secret"  # intentionally weak, lab-only

app = Flask(__name__)


def init_db():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("DROP TABLE IF EXISTS users")
    cur.execute(
        """CREATE TABLE users (
            id INTEGER PRIMARY KEY,
            username TEXT,
            email TEXT,
            ssn TEXT,
            balance REAL
        )"""
    )
    seed = [
        (1, "alice", "alice@corp.test", "111-22-3333", 4200.50),
        (2, "bob", "bob@corp.test", "222-33-4444", 900.00),
        (3, "carol", "carol@corp.test", "333-44-5555", 15000.75),
        (4, "dave", "dave@corp.test", "444-55-6666", 50.00),
    ]
    cur.executemany("INSERT INTO users VALUES (?,?,?,?,?)", seed)
    conn.commit()
    conn.close()


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
    return g.db


def log_event(event: dict):
    event["timestamp"] = datetime.now(timezone.utc).isoformat()
    os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
    with open(LOG_PATH, "a") as f:
        f.write(json.dumps(event) + "\n")


@app.before_request
def log_request():
    g.start_time = time.time()


@app.after_request
def after(response):
    log_event(
        {
            "path": request.path,
            "method": request.method,
            "query": request.query_string.decode("utf-8", errors="ignore"),
            "args": request.args.to_dict(),
            "headers_authorization": request.headers.get("Authorization", ""),
            "source_ip": request.remote_addr,
            "status_code": response.status_code,
            "duration_ms": round((time.time() - g.get("start_time", time.time())) * 1000, 2),
        }
    )
    return response


# --- VULN 1: SQL Injection (string-concatenated query, no parameterization) ---
@app.route("/users/search")
def users_search():
    name = request.args.get("name", "")
    conn = get_db()
    cur = conn.cursor()
    query = f"SELECT id, username, email FROM users WHERE username = '{name}'"
    try:
        cur.execute(query)
        rows = cur.fetchall()
    except sqlite3.Error as e:
        return jsonify({"error": str(e), "query": query}), 400
    return jsonify(
        {"results": [{"id": r[0], "username": r[1], "email": r[2]} for r in rows]}
    )


# --- VULN 2: IDOR (no ownership / auth check on resource access) ---
@app.route("/users/<int:user_id>/profile")
def user_profile(user_id):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT id, username, email, ssn, balance FROM users WHERE id = ?", (user_id,))
    row = cur.fetchone()
    if not row:
        return jsonify({"error": "not found"}), 404
    return jsonify(
        {"id": row[0], "username": row[1], "email": row[2], "ssn": row[3], "balance": row[4]}
    )


# --- VULN 3: Broken JWT verification (accepts alg=none, no signature check) ---
@app.route("/account")
def account():
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return jsonify({"error": "missing bearer token"}), 401
    token = auth.split(" ", 1)[1]
    try:
        # VULNERABLE: verify=False / algorithms include 'none'
        payload = jwt.decode(
            token, JWT_SECRET, algorithms=["HS256", "none"], options={"verify_signature": False}
        )
    except Exception as e:
        return jsonify({"error": f"invalid token: {e}"}), 401

    user_id = payload.get("user_id")
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT id, username, balance FROM users WHERE id = ?", (user_id,))
    row = cur.fetchone()
    if not row:
        return jsonify({"error": "user not found"}), 404
    return jsonify({"id": row[0], "username": row[1], "balance": row[2], "claims": payload})


@app.route("/health")
def health():
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5060)
