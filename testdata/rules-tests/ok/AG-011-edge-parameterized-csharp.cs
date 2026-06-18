// Edge case: SQL uses parameterized queries with positional params
public class UserRepository
{
    private readonly string _connString;

    public UserRepository(IConfiguration config)
    {
        _connString = config.GetConnectionString("DefaultConnection");
    }

    public User GetUserById(int id)
    {
        using var conn = new SqlConnection(_connString);
        var cmd = new SqlCommand("SELECT id, username, email FROM users WHERE id = @Id", conn);
        cmd.Parameters.AddWithValue("@Id", id);
        conn.Open();
        using var reader = cmd.ExecuteReader();
        if (reader.Read())
        {
            return new User { Id = reader.GetInt32(0), Username = reader.GetString(1) };
        }
        return null;
    }

    public List<User> SearchUsers(string searchTerm)
    {
        using var conn = new SqlConnection(_connString);
        var cmd = new SqlCommand(
            "SELECT id, username, email FROM users WHERE username LIKE @Search",
            conn
        );
        cmd.Parameters.AddWithValue("@Search", $"%{searchTerm}%");
        conn.Open();
        // ...
    }
}
