import msgpack
from flask import request
def load_session():
    raw = request.cookies.get("session", b"")
    data = msgpack.unpackb(raw, strict_map_key=False)
    return data
