# PY-017 V4: `if $VAR:` (without `not`) variant + all variable names
# Exercises: role, is_admin, account, permission, auth, api_key, secret
from flask import Flask, redirect, render_template, request

app = Flask(__name__)


@app.route("/role-check")
def role_check():
    role = request.headers.get("X-Role", "")
    if role:  # VULN: truthiness on role
        return render_template("admin.html")
    return redirect("/login")


@app.route("/admin-panel")
def admin_panel():
    is_admin = request.args.get("is_admin", False)
    if is_admin:  # VULN: truthiness on is_admin
        return render_template("admin_panel.html")
    return redirect("/")


@app.route("/account-info")
def account_info():
    account = request.cookies.get("account_id")
    if account:  # VULN: truthiness on account
        return render_template("account.html", account=account)
    return redirect("/login")


@app.route("/check-permission")
def check_permission():
    permission = request.args.get("perm")
    if permission:  # VULN: truthiness on permission
        return "Access granted"
    return "Access denied"


@app.route("/api-auth")
def api_auth():
    auth = request.headers.get("Authorization")
    if auth:  # VULN: truthiness on auth
        return "Authenticated"
    return "Unauthenticated"


@app.route("/api-key-access")
def api_key_access():
    api_key = request.args.get("api_key")
    if api_key:  # VULN: truthiness on api_key
        return jsonify({"data": "sensitive"})
    return jsonify({"error": "unauthorized"}), 401


@app.route("/secret-access")
def secret_access():
    secret = request.headers.get("X-Secret")
    if secret:  # VULN: truthiness on secret
        return "Secret area"
    return "Access denied"
