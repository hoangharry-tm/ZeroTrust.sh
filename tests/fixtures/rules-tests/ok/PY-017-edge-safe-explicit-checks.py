# PY-017 EDGE/SAFE: explicit checks for all variable names
# Uses is None, == "", or != 0 — should NOT fire truthiness rule
from flask import Flask, request, jsonify

app = Flask(__name__)


@app.route("/safe-role")
def safe_role():
    role = request.headers.get("X-Role")
    if role is None:
        return "No role"
    return "Role: " + role


@app.route("/safe-is-admin")
def safe_is_admin():
    is_admin = request.args.get("is_admin")
    if is_admin == "true":
        return "Admin panel"
    return "User panel"


@app.route("/safe-account")
def safe_account():
    account = request.cookies.get("account_id")
    if account == "":
        return redirect("/login")
    return "Account: " + account


@app.route("/safe-permission")
def safe_permission():
    permission = request.args.get("perm")
    if permission != "admin":
        return "Access denied"
    return "Access granted"


@app.route("/safe-auth-header")
def safe_auth():
    auth = request.headers.get("Authorization")
    if auth is None or auth == "":
        return jsonify({"error": "unauthorized"}), 401
    return jsonify({"status": "ok"})


@app.route("/safe-api-key")
def safe_api_key():
    api_key = request.args.get("api_key")
    if api_key is None or len(api_key) < 32:
        return jsonify({"error": "invalid key"}), 401
    return jsonify({"data": "sensitive"})


@app.route("/safe-secret")
def safe_secret():
    secret = request.headers.get("X-Secret")
    if secret is None:
        return jsonify({"error": "missing"}), 401
    return jsonify({"status": "ok"})
