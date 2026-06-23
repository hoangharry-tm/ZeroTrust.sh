# PY-017 V3: Django view with truthiness check on user and token
# Realistic AI-generated profile view — bypasseable truthiness guards
from django.http import HttpRequest, JsonResponse, HttpResponse
from django.shortcuts import redirect


def profile_view(request: HttpRequest) -> HttpResponse:
    """Display user profile page."""
    user_id = request.session.get("user_id")
    if not user_id:  # VULN: user_id=0 bypasses
        return redirect("/login/")

    user = get_user_by_id(user_id)
    if not user:  # VULN: falsy user dict bypasses
        return redirect("/login/")

    return JsonResponse({"username": user["name"], "email": user["email"]})


def admin_panel(request: HttpRequest) -> HttpResponse:
    """Admin panel with truthiness auth."""
    token = request.headers.get("X-Auth-Token", "")
    if not token:  # VULN: empty token bypasses
        return JsonResponse({"error": "Unauthorized"}, status=401)

    session = get_session(token)
    if not session:  # VULN: falsy session dict bypasses
        return JsonResponse({"error": "Invalid session"}, status=401)

    return JsonResponse({"admin_data": "classified"})
