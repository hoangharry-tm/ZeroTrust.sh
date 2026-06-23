# PY-017 EDGE/SAFE: Property access pattern — not a truthiness check on variable
# Near-miss: "if user.is_authenticated:" doesn't match because $VAR is user.is_authenticated
from flask import Flask, redirect, render_template, request

app = Flask(__name__)


@app.route("/dashboard")
def dashboard():
    """Safe: uses property access instead of bare truthiness check."""
    user_id = request.cookies.get("session_id")
    user = lookup_session(user_id)
    if user is not None and user.is_authenticated:
        return render_template("dashboard.html", user=user)
    return redirect("/login")


@app.route("/settings")
def settings():
    """Safe: checks a boolean field, not the whole user object."""
    user = get_current_user()
    if user.is_admin:
        return render_template("admin_settings.html", user=user)
    return render_template("user_settings.html", user=user)
