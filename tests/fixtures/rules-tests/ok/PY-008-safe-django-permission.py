# PY-008 SAFE: Django permission class with real access control logic
# Safe: properly checks user roles, not unconditional return True
from django.http import HttpRequest


class AdminPermission:
    """Proper admin permission check."""

    def has_permission(self, request: HttpRequest) -> bool:
        if not request.user or not request.user.is_authenticated:
            return False
        return request.user.is_staff or request.user.is_superuser


class EditorPermission:
    """Proper editor permission with object-level check."""

    def has_object_permission(self, request, view, obj) -> bool:
        if not request.user or not request.user.is_authenticated:
            return False
        if request.user.is_superuser:
            return True
        if hasattr(obj, "owner") and obj.owner == request.user:
            return True
        return False
