def get_profile(request):
    user_id = request.GET.get("user_id")
    if user_id is not None:
        return db.query(User).get(user_id)
    return redirect("/login")


def verify_session(request):
    token = request.headers.get("Authorization")
    if token is None or token == "":
        return False
    return validate_token(token)
