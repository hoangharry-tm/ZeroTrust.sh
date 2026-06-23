from flask import request, Markup
def render_greeting():
    name = request.args.get("name", "")
    return f"<h1>Hello, {Markup(name)}</h1>"
