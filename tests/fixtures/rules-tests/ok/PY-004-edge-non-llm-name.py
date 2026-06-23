# PY-004 EDGE/SAFE: Function name does NOT match LLM pattern
# Near-miss: a function that does internal data processing, not an LLM call
from flask import Flask, request, jsonify

app = Flask(__name__)


def process_order(order_data: dict) -> dict:
    """Process an order — NOT an LLM call despite having data processing."""
    total = sum(item["price"] * item["quantity"] for item in order_data.get("items", []))
    tax = total * 0.08
    return {"subtotal": total, "tax": tax, "total": total + tax}


@app.route("/checkout", methods=["POST"])
def checkout():
    """Checkout endpoint — process_order is not an LLM sink."""
    data = request.get_json()
    result = process_order(data)
    return jsonify(result)
