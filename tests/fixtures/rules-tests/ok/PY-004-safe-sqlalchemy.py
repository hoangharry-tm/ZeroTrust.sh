# PY-004 SAFE: SQLAlchemy query() must NOT fire (excluded by pattern-not-inside)
import sqlalchemy
from sqlalchemy.orm import Session
from flask import Flask, request, jsonify

app = Flask(__name__)
engine = sqlalchemy.create_engine("sqlite:///test.db")


@app.route("/search")
def search():
    """SQLAlchemy query — excluded by pattern-not-inside."""
    q = request.args.get("q", "")
    with Session(engine) as session:
        results = session.query(User).filter(User.name.contains(q)).all()
    return jsonify({"users": [u.to_dict() for u in results]})
