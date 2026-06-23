var userId = Request.Query["id"];
var cmd = new SqlCommand("SELECT * FROM users WHERE id = @id");
cmd.Parameters.AddWithValue("@id", userId);
cmd.ExecuteQuery();
context.Database.ExecuteSqlRaw("DELETE FROM sessions WHERE id = @id", sessionId);
