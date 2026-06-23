from flask import request, escape
def render_greeting():
    name = escape(request.args.get("name", ""))
    return f"<h1>Hello, {name}</h1>"
