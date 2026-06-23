import requests
from flask import request
from urllib.parse import urlparse
ALLOWED_HOSTS = {"api.internal.corp", "data.internal.corp"}
def fetch_url():
    url = request.args.get("url", "")
    if urlparse(url).hostname not in ALLOWED_HOSTS:
        return "blocked", 403
    return requests.get(url).text
