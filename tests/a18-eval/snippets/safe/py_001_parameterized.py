def get_user(conn, user_id):
    query = "SELECT * FROM users WHERE id = ?"
    return conn.execute(query, (user_id,)).fetchone()
