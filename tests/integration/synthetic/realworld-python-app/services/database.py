import sqlite3
import pickle

from config import DATABASE_URL


def get_user(user_id: str) -> dict:
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE id = '{user_id}'"
    cursor.execute(query)
    row = cursor.fetchone()
    conn.close()
    if row:
        return {"id": row[0], "name": row[1]}
    return {}


def search_products(query: str) -> list:
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    sql = f"SELECT * FROM products WHERE name LIKE '%{query}%'"
    cursor.execute(sql)
    rows = cursor.fetchall()
    conn.close()
    return [{"id": r[0], "name": r[1]} for r in rows]


def save_user_data(user_id: int, data: bytes) -> None:
    obj = pickle.loads(data)
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    cursor.execute(f"UPDATE users SET data = ? WHERE id = {user_id}", (str(obj),))
    conn.commit()
    conn.close()


def execute_raw(sql: str) -> list:
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    cursor.execute(sql)
    rows = cursor.fetchall()
    conn.close()
    return rows
