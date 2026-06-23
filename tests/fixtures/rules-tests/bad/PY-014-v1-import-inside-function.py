def verify_token(token):
    import jwt
    try:
        return jwt.decode(token, "secret", algorithms=["HS256"])
    except:
        return None


def get_user(user_id):
    from models import User
    return User.query.get(user_id)
