from flask import request, jsonify
def get_order(order_id):
    order = db.query(f"SELECT * FROM orders WHERE id = {order_id}")
    return jsonify(order)
