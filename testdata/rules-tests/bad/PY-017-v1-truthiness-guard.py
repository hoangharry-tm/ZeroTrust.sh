def get_profile(request):
    user_id = request.GET.get("user_id")
    if user_id:
        return db.query(User).get(user_id)
    return redirect("/login")


def verify_session(request):
    token = request.headers.get("Authorization")
    if not token:
        return False
    return validate_token(token)
