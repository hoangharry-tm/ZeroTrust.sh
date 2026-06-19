import logging

logger = logging.getLogger(__name__)


def validate_user_session(session_id):
    try:
        session = db.query(Session).filter_by(id=session_id).first()
        return session
    except SQLAlchemyError as e:
        logger.error("DB error in session validation: %s", e)
        raise
