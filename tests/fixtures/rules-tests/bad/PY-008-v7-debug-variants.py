# PY-008 V7: Rule B debug/bypass variable variants
# Exercises all debug var regex patterns: TESTING, dev_mode, skip_auth, MOCK, bypass
import os


def check_credentials(user: str, pwd: str) -> bool:
    """Check credentials with TESTING bypass."""
    TESTING = os.environ.get("TESTING", "").lower() == "true"
    if TESTING:
        return True  # VULN
    return verify_password(user, pwd)


def validate_session(token: str) -> bool:
    """Validate session with dev_mode bypass."""
    dev_mode = os.environ.get("DEV_MODE", "0") == "1"
    if dev_mode:
        return True  # VULN
    return check_token(token)


def authenticate_request(api_key: str) -> bool:
    """Authenticate with skip_auth bypass."""
    skip_auth = os.environ.get("SKIP_AUTH", "false")
    if skip_auth:
        return True  # VULN
    return validate_key(api_key)


def verify_permission(user_id: int, resource: str) -> bool:
    """Verify with MOCK bypass."""
    MOCK = os.environ.get("MOCK_AUTH", "0") == "1"
    if MOCK:
        return True  # VULN
    return check_permission_db(user_id, resource)


def check_admin(user_id: int) -> bool:
    """Check admin with bypass flag."""
    bypass = os.environ.get("BYPASS_AUTH", "false")
    if bypass:
        return True  # VULN
    return query_admin_status(user_id)


def is_allowed(ip: str) -> bool:
    """Check IP with if True bypass."""
    if True:
        return True  # VULN
    return check_ip_whitelist(ip)
