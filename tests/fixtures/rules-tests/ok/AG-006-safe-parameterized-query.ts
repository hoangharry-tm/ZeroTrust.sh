const userId = req.query.id;
db.query("SELECT * FROM users WHERE id = ?", [userId]);
connection.execute("UPDATE accounts SET balance = ? WHERE user = ?", [0, user]);
db.query(`SELECT * FROM users WHERE id = $1`, [userId]);
