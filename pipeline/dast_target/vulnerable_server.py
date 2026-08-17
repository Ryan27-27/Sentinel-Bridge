# DEMO TARGET — intentionally vulnerable Flask app.
# This exists ONLY so the DAST engine has a real, live HTTP server to scan.
# Never deploy this anywhere real; it's deliberately insecure for demonstration.

from flask import Flask, request, make_response

app = Flask(__name__)

# Intentionally missing security headers (no CSP, no X-Frame-Options, no HSTS)


@app.route("/")
def home():
    resp = make_response("<h1>Demo Vulnerable App</h1><p>Used as a DAST scan target.</p>")
    # finding: missing Content-Security-Policy
    # finding: missing X-Frame-Options
    # finding: Server header leaks version info (Flask default behavior)
    return resp


@app.route("/search")
def search():
    q = request.args.get("q", "")
    # finding: reflected XSS — user input echoed back without escaping
    return f"<html><body>Search results for: {q}</body></html>"


@app.route("/login", methods=["GET", "POST"])
def login():
    resp = make_response("<form method='post'><input name='user'><input name='pass' type='password'>"
                          "<button>Login</button></form>")
    # finding: cookie set without Secure or HttpOnly flag
    resp.set_cookie("session_id", "demo-session-12345")
    return resp


@app.route("/api/users/<user_id>")
def user_profile(user_id):
    # finding: IDOR — no authorization check, any user_id returns data
    return {"user_id": user_id, "email": f"user{user_id}@example.com", "role": "member"}


@app.route("/redirect")
def open_redirect():
    target = request.args.get("next", "/")
    # finding: open redirect — no validation that `next` is a safe internal path
    resp = make_response("", 302)
    resp.headers["Location"] = target
    return resp


@app.errorhandler(500)
def server_error(e):
    # finding: verbose error message could leak stack trace in debug mode
    return f"Internal error: {e}", 500


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5050, debug=False)
