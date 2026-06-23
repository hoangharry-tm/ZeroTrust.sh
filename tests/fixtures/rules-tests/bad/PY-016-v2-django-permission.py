# PY-016 V2: Django permission class with return True but no return False
# Realistic AI-generated permission system — always grants access
from django.http import HttpRequest


class IsStaffPermission:
    """Custom permission that should check staff status."""

    def has_permission(self, request: HttpRequest) -> bool:
        """Check if user is staff member."""
        return True  # VULN: always returns True, no return False


class HasRolePermission:
    """Permission based on user role."""

    def has_object_permission(self, request, view, obj) -> bool:
        """Check if user has the required role for this object."""
        return True  # VULN: always returns True
