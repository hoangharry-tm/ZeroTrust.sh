import requests
from flask import request
def fetch_url():
    url = request.args.get("url")
    return requests.get(url).text
