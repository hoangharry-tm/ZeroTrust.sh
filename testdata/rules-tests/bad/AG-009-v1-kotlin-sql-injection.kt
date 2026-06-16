val userId = request.getParameter("id")
val sql = "SELECT * FROM users WHERE id = " + userId
val stmt = connection.createStatement()
stmt.executeQuery(sql)
connection.createStatement().executeUpdate("UPDATE accounts SET balance = 0 WHERE user = " + reqBody.user)
db.execRaw("DELETE FROM sessions WHERE id = $sessionId")
