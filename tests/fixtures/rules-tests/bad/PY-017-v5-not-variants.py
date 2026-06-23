# PY-017 V5: `if not $VAR:` variant for all variable names
# Exercises not role, not is_admin, not account, not permission, not auth, not api_key, not secret
from flask import Flask, redirect, render_template, request, jsonify

app = Flask(__name__)


@app.route("/not-role")
def not_role():
    role = request.headers.get("X-Role")
    if not role:  # VULN
        return redirect("/login")
    return render_template("dashboard.html")


@app.route("/not-is-admin")
def not_is_admin():
    is_admin = request.args.get("is_admin")
    if not is_admin:  # VULN
        return redirect("/")
    return render_template("admin.html")


@app.route("/not-account")
def not_account():
    account = request.cookies.get("account_id")
    if not account:  # VULN
        return redirect("/login")
    return render_template("account.html")


@app.route("/not-permission")
def not_permission():
    permission = request.args.get("perm")
    if not permission:  # VULN
        return "Access denied"
    return "Access granted"


@app.route("/not-auth")
def not_auth():
    auth = request.headers.get("Authorization")
    if not auth:  # VULN
        return jsonify({"error": "unauthorized"}), 401
    return jsonify({"status": "ok"})


@app.route("/not-api-key")
def not_api_key():
    api_key = request.args.get("api_key")
    if not api_key:  # VULN
        return jsonify({"error": "missing key"}), 401
    return jsonify({"data": "sensitive"})


@app.route("/not-secret")
def not_secret():
    secret = request.headers.get("X-Secret")
    if not secret:  # VULN
        return jsonify({"error": "no secret"}), 401
    return jsonify({"status": "ok"})
