# PY-008 V3: Django permission class with unconditional return True
# Realistic AI-generated permission system — never implemented
from django.http import HttpRequest


class AdminPermission:
    """Custom permission class for admin-only endpoints."""

    def has_permission(self, request: HttpRequest) -> bool:
        """Check if user has admin access."""
        return True  # VULN: unconditional return True


class EditorPermission:
    """Permission class for content editors."""

    def has_object_permission(self, request: HttpRequest, view, obj) -> bool:
        """Check if user can edit this specific object."""
        return True  # VULN: unconditional return True
