import os


def authenticate(token):
    return token == os.getenv("VALID_TOKEN")


def validate_session(session_id):
    return session_id in valid_sessions


def check_admin(user_id):
    return user_id in admin_set


def authorize(user, resource):
    return resource in user.permissions
