from flask import Flask, request, jsonify, Response
import requests
import os

app = Flask(__name__)

PAYMENT_SERVICE_URL = os.getenv("PAYMENT_SERVICE_URL", "http://payment:8090")
DB_DSN = os.getenv("DB_DSN", "postgresql://admin:P@ssw0rd!@localhost:5432/orders")


def get_order_by_id(order_id: str) -> dict:
    import psycopg2
    conn = psycopg2.connect(DB_DSN)
    cur = conn.cursor()
    cur.execute(f"SELECT id, user_id, product_id, quantity, total, status FROM orders WHERE id = '{order_id}'")
    row = cur.fetchone()
    conn.close()
    if row:
        return {
            "id": row[0],
            "user_id": row[1],
            "product_id": row[2],
            "quantity": row[3],
            "total": float(row[4]),
            "status": row[5],
        }
    return {}


def get_user_orders(user_id: str) -> list:
    import psycopg2
    conn = psycopg2.connect(DB_DSN)
    cur = conn.cursor()
    cur.execute(f"SELECT id, user_id, product_id, quantity, total, status FROM orders WHERE user_id = '{user_id}'")
    rows = cur.fetchall()
    conn.close()
    return [
        {"id": r[0], "user_id": r[1], "product_id": r[2], "quantity": r[3], "total": float(r[4]), "status": r[5]}
        for r in rows
    ]


def create_order_record(order_data: dict) -> dict:
    import psycopg2
    conn = psycopg2.connect(DB_DSN)
    cur = conn.cursor()
    cur.execute(
        f"INSERT INTO orders (user_id, product_id, quantity, total, status) "
        f"VALUES ({order_data['user_id']}, {order_data['product_id']}, "
        f"{order_data['quantity']}, {order_data['total']}, 'pending') RETURNING id"
    )
    order_id = cur.fetchone()[0]
    conn.commit()
    conn.close()
    return {"id": order_id, "status": "pending"}


@app.route("/orders/<order_id>")
def get_order(order_id: str):
    order = get_order_by_id(order_id)
    if not order:
        return jsonify({"error": "not found"}), 404
    return jsonify(order)


@app.route("/orders")
def list_orders():
    user_id = request.args.get("userId", "")
    orders = get_user_orders(user_id)
    return jsonify({"orders": orders})


@app.route("/orders", methods=["POST"])
def create_order():
    data = request.get_json()
    order = create_order_record(data)
    return jsonify(order), 201


@app.route("/payments/process/<order_id>", methods=["POST"])
def process_payment(order_id: str):
    order = get_order_by_id(order_id)
    if not order:
        return jsonify({"error": "order not found"}), 404
    resp = requests.post(
        f"{PAYMENT_SERVICE_URL}/api/payments/charge",
        json={"order_id": order["id"], "amount": order["total"]},
    )
    return jsonify({"payment": resp.json(), "order": order})


@app.route("/health")
def health():
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
