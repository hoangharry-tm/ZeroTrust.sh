import pickle, base64
from flask import request
def load_session():
    data = base64.b64decode(request.cookies.get("session"))
    return pickle.loads(data)
