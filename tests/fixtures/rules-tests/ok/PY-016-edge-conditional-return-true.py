# PY-016 EDGE/SAFE: Auth function with return True inside if block
# Near-miss: return True exists but it's inside a conditional, and return False exists
def has_access(user_id: int, resource_owner_id: int) -> bool:
    """Check access: return True only inside conditional blocks."""
    if user_id == resource_owner_id:
        return True
    return False


def is_admin(user_id: int) -> bool:
    """Check admin status with proper conditions."""
    from cache import get_user_role
    role = get_user_role(user_id)
    return role == "admin"
