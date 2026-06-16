const userId = req.query.id;
db.query(`SELECT * FROM users WHERE id = ${userId}`);
connection.execute(`UPDATE accounts SET balance = 0 WHERE user = ${req.body.user}`);
db.run(`DELETE FROM sessions WHERE id = ` + sessionId);
