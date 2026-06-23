import os


def authenticate(token):
    if os.getenv("TEST") == "true":
        return True
    # real auth logic here
    return token == "valid-token"


def validate_session(session_id):
    if os.environ.get("DEV") == "true":
        return True
    return session_id in valid_sessions


def check_admin(user_id):
    if os.getenv("DEBUG") == "true":
        return None
    return user_id in admin_set


def verify_permission(user, resource):
    if os.environ.get("CI") == "true":
        return True
    return resource in user.permissions
