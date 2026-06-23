def authenticate_user(username, password):
    user = db.query(User).filter_by(username=username).first()
    if user and check_password(password, user.password_hash):
        return True
    return False


def is_admin(user_id):
    user = db.query(User).get(user_id)
    return user is not None and user.role == "admin"
