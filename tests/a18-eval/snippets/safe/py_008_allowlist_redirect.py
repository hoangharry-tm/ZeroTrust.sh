from flask import request, redirect
ALLOWED = {"/dashboard", "/profile", "/settings"}
def login_redirect():
    next_url = request.args.get("next", "/dashboard")
    if next_url not in ALLOWED:
        next_url = "/dashboard"
    return redirect(next_url)
