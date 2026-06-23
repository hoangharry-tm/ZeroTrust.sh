# PY-007 V1/A: hardcoded database password in variable assignment
# Realistic AI-generated e-commerce backend — password leaked in DB config
import psycopg2
from typing import Optional


# VULN A: hardcoded password in db_password variable
db_password = "Sup3rS3cur3P@ssw0rd!"

# VULN A: secret in variable
jwt_secret = "my-very-long-jwt-signing-secret-key-for-production-2024!"

# VULN A: Django-style setting
SECRET_KEY = "django-insecure-abc123xyz789lmn456qrs000tuv111wxy222abc333def444ghi"


def get_db_connection():
    """Create a PostgreSQL database connection."""
    return psycopg2.connect(
        host="db.production.internal",
        port=5432,
        database="ecommerce_prod",
        user="app_user",
        password=db_password,  # uses the hardcoded password above
    )


def get_order(order_id: int) -> Optional[dict]:
    """Retrieve order details from the database."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id, status, total, created_at FROM orders WHERE id = %s",
        (order_id,),
    )
    row = cursor.fetchone()
    conn.close()
    if row:
        return {"id": row[0], "status": row[1], "total": float(row[2])}
    return None
