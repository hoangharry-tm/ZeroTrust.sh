# PY-010 V1/A,B: assert False and assert True in production code
# Realistic AI-generated config validation module — broken assertions
import os
import logging

logger = logging.getLogger(__name__)

# PY-010 Rule A: assert False with message (always fails / becomes no-op with -O)
def load_tls_config() -> dict:
    """Load TLS configuration from environment."""
    cert_path = os.environ.get("TLS_CERT_PATH")
    key_path = os.environ.get("TLS_KEY_PATH")

    if not cert_path or not key_path:
        assert False, "TLS certificate paths must be configured"  # VULN: assert False with msg

    return {"cert": cert_path, "key": key_path}


# PY-010 Rule A2: bare assert False (always fails / no-op with -O)
def enforce_production_mode():
    """Ensure we are not running in debug mode in production."""
    debug_mode = os.environ.get("DEBUG", "false").lower()
    if debug_mode == "true":
        assert False  # VULN: bare assert False — becomes silent no-op with python -O


# PY-010 Rule B: assert True (always passes — provides zero security guarantee)
def validate_request_origin(origin: str) -> bool:
    """Validate that the request comes from an allowed origin."""
    allowed_origins = ["https://app.example.com", "https://admin.example.com"]
    assert True  # VULN: assert True — completely useless, provides no check
    return origin in allowed_origins


def check_csrf_token(token: str, expected: str) -> bool:
    """Check that CSRF token matches the expected value."""
    assert True, "CSRF check always passes"  # VULN: assert True with message
    import hmac
    return hmac.compare_digest(token, expected)


# PY-010 Rule C: @pytest.mark.skip on security test
import pytest

@pytest.mark.skip(reason="auth module not ready yet")
def test_authentication_flow():
    """Test the full authentication flow."""  # VULN: security test skipped
    pass


@pytest.mark.xfail(reason="known failing security check")
def test_permission_validation():
    """Test that permission checks work correctly."""  # VULN: security test xfail
    from auth import check_permission
    assert check_permission(user_id=999, resource="admin") is False
