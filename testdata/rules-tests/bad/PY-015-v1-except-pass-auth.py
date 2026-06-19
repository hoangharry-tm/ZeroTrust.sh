def validate_user_session(session_id):
    try:
        session = db.query(Session).filter_by(id=session_id).first()
        return session
    except:
        pass
    return None
