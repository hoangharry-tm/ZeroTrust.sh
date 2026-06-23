from flask import request, jsonify, g
def get_order(order_id):
    order = db.query("SELECT * FROM orders WHERE id = ?", (order_id,))
    if order["user_id"] != g.current_user.id:
        return jsonify(error="forbidden"), 403
    return jsonify(order)
