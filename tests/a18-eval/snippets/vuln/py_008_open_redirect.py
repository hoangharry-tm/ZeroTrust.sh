from flask import request, redirect
def login_redirect():
    next_url = request.args.get("next", "/dashboard")
    return redirect(next_url)
