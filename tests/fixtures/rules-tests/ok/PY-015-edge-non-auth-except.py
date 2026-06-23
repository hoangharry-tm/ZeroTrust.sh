# PY-015 EDGE/SAFE: except: pass in a non-auth utility function
# Near-miss: pattern exists but function name doesn't match auth regex
from flask import Flask, request, jsonify

app = Flask(__name__)


def format_response(data: dict) -> dict:
    """Format API response — not an auth function."""
    try:
        return {"status": "ok", "data": data, "timestamp": current_timestamp()}
    except:
        pass  # safe: this is a formatting function, not auth
    return {"status": "error", "data": None}


def parse_pagination_params(request) -> dict:
    """Parse pagination parameters from request — not an auth function."""
    try:
        page = int(request.args.get("page", 1))
        per_page = min(int(request.args.get("per_page", 20)), 100)
        return {"page": page, "per_page": per_page}
    except:
        pass  # safe: pagination parsing, not security
    return {"page": 1, "per_page": 20}
