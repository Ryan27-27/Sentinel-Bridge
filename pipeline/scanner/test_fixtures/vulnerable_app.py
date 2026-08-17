# DEMO FIXTURE — intentionally vulnerable code used to demonstrate the SAST scanner.
# This file is NEVER deployed; it exists purely so `sentinel scan` has real findings to surface.

import os
import pickle
import hashlib
import sqlite3

DEBUG = True  # finding: debug mode enabled

AWS_SECRET_KEY = "AKIAABCDEFGHIJKLMNOP"  # finding: AWS key pattern (demo value, not real)
api_key = "sk_live_51Hxyz0000000000000000abcdef"  # finding: generic hardcoded secret


def get_user(conn, username):
    cursor = conn.cursor()
    # finding: SQL injection via string formatting
    query = "SELECT * FROM users WHERE username = '%s'" % username
    cursor.execute(query)
    return cursor.fetchone()


def get_user_fstring(conn, user_id):
    cursor = conn.cursor()
    # finding: SQL injection via f-string
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
    return cursor.fetchone()


def run_diagnostic(cmd):
    # finding: command injection via os.system
    os.system(cmd)


def load_config(data):
    # finding: insecure deserialization
    return pickle.loads(data)


def hash_password(password):
    # finding: weak hash algorithm
    return hashlib.md5(password.encode()).hexdigest()


def evaluate_expression(expr):
    # finding: eval usage
    return eval(expr)
