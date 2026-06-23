# PY-009 V3: Django middleware with TODO + pass and commented validation
# Realistic AI-generated security middleware — controls never implemented
import logging
from django.http import HttpRequest, HttpResponse

logger = logging.getLogger(__name__)


class InputValidationMiddleware:
    """Middleware that should validate all incoming request data."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request: HttpRequest) -> HttpResponse:
        # validate request body for injection patterns
        # TODO: implement input sanitization
        pass  # VULN: pass stub

        # sanitize all query parameters
        # FIXME: add parameter whitelist
        pass  # VULN: pass stub

        return self.get_response(request)


def sanitize_request_data(data: dict) -> dict:
    """Sanitize request payload to prevent injection attacks."""
    # TODO: strip dangerous characters from all string fields
    return data  # VULN: returns unsanitized data
