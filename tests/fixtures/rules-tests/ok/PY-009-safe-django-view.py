# PY-009 SAFE: Django view with proper input validation implemented
# Safe: validation functions have real logic, not stubs
from django.http import HttpRequest, JsonResponse
from django.views import View
import json
import re


def sanitize_user_input(value: str) -> str:
    """Properly sanitize user input by stripping dangerous characters."""
    sanitized = re.sub(r'[<>\'";]', '', value)
    return sanitized[:1000]


def validate_email(email: str) -> bool:
    """Proper email validation with regex."""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, email))


class UserRegistrationView(View):
    """Safe user registration with real validation."""

    def post(self, request):
        body = json.loads(request.body)
        email = body.get("email", "")
        username = body.get("username", "")

        if not validate_email(email):
            return JsonResponse({"error": "Invalid email"}, status=400)

        safe_username = sanitize_user_input(username)
        return JsonResponse({"status": "created", "username": safe_username})
