import jwt
from models import User


def verify_token(token):
    try:
        return jwt.decode(token, "secret", algorithms=["HS256"])
    except:
        return None


def get_user(user_id):
    return User.query.get(user_id)
