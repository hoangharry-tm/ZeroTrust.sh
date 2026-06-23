# PY-017 SAFE: Django view with explicit None and empty checks
# Safe: uses "is None" and "!= ''" instead of truthiness
from django.http import HttpRequest, JsonResponse, HttpResponse
from django.shortcuts import redirect


def profile_view(request: HttpRequest) -> HttpResponse:
    """Safe: explicit None and string length checks."""
    user_id = request.session.get("user_id")
    if user_id is None:
        return redirect("/login/")

    user = get_user_by_id(user_id)
    if user is None:
        return redirect("/login/")

    return JsonResponse({"username": user["name"]})


def admin_panel(request: HttpRequest) -> HttpResponse:
    """Safe: explicit empty-string check for token."""
    token = request.headers.get("X-Auth-Token", "")
    if token == "":
        return JsonResponse({"error": "Unauthorized"}, status=401)

    return JsonResponse({"admin_data": "classified"})
