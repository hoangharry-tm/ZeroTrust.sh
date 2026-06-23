# PY-015 SAFE: Flask blueprint with proper exception handling — no except:pass
# Safe: exceptions are logged and handled properly
import logging
from flask import Blueprint, request, jsonify

auth_bp = Blueprint("auth", __name__)
logger = logging.getLogger(__name__)


@auth_bp.before_request
def authenticate_request():
    """Safe session validation with proper error handling."""
    try:
        session_id = request.cookies.get("session_id")
        if session_id:
            user = lookup_session(session_id)
            request.user = user
    except Exception as e:
        logger.error("Session lookup failed: %s", str(e))
        request.user = None
