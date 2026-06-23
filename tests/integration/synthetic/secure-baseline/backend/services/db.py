from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from config import get_database_url

engine = create_engine(get_database_url())
Session = sessionmaker(bind=engine)


def get_user_by_id(user_id: int) -> dict:
    with Session() as session:
        result = session.execute(
            text("SELECT id, username, role FROM users WHERE id = :user_id"),
            {"user_id": user_id},
        )
        row = result.fetchone()
        if row:
            return {"id": row[0], "username": row[1], "role": row[2]}
        return {}


def search_products(query: str) -> list:
    with Session() as session:
        search_term = f"%{query}%"
        result = session.execute(
            text("SELECT id, name, price FROM products WHERE name ILIKE :search"),
            {"search": search_term},
        )
        return [{"id": r[0], "name": r[1], "price": float(r[2])} for r in result]


def get_orders_by_user(user_id: int) -> list:
    with Session() as session:
        result = session.execute(
            text("SELECT id, product_id, quantity, status FROM orders WHERE user_id = :uid"),
            {"uid": user_id},
        )
        return [{"id": r[0], "product_id": r[1], "quantity": r[2], "status": r[3]} for r in result]
