var userId = Request.Query["id"];
var cmd = new SqlCommand();
cmd.ExecuteQuery("SELECT * FROM users WHERE id = " + userId);
cmd.ExecuteNonQuery("UPDATE accounts SET balance = 0 WHERE user = " + user);
context.Database.ExecuteSqlRaw("DELETE FROM sessions WHERE id = " + sessionId);
