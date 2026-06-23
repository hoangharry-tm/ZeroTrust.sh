# PY-015 EDGE/SAFE: except: pass in non-auth-named functions
# Near-miss: pattern exists but function name doesn't match auth regex
from flask import Flask, request, jsonify

app = Flask(__name__)


def format_api_response(data: dict, status: int = 200) -> dict:
    """Format API response — not an auth function."""
    try:
        return {"status": status, "data": data, "timestamp": current_timestamp()}
    except:
        pass
    return {"status": 500, "data": None}


def parse_pagination(request):
    """Parse pagination — not an auth function."""
    try:
        page = int(request.args.get("page", 1))
        per_page = min(int(request.args.get("per_page", 20)), 100)
        return {"page": page, "per_page": per_page}
    except:
        pass
    return {"page": 1, "per_page": 20}


def serialize_user(obj):
    """Serialize user object — not an auth function."""
    try:
        return {"id": obj.id, "name": obj.name}
    except:
        pass
    return {}
