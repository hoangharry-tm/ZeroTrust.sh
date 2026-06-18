import java.sql.Connection
import java.sql.DriverManager
import java.sql.PreparedStatement

class SafeUserRepository(private val dbUrl: String, private val dbUser: String, private val dbPass: String) {

    private val connection: Connection by lazy {
        DriverManager.getConnection(dbUrl, dbUser, dbPass)
    }

    fun getUserById(id: Int): User? {
        val sql = "SELECT id, username, email, role FROM users WHERE id = ?"
        val stmt: PreparedStatement = connection.prepareStatement(sql)
        stmt.setInt(1, id)
        val rs = stmt.executeQuery()
        return if (rs.next()) {
            User(
                id = rs.getInt("id"),
                username = rs.getString("username"),
                email = rs.getString("email"),
                role = rs.getString("role")
            )
        } else null
    }

    fun searchUsers(searchTerm: String): List<User> {
        val sql = "SELECT id, username, email, role FROM users WHERE username ILIKE ?"
        val stmt: PreparedStatement = connection.prepareStatement(sql)
        stmt.setString(1, "%$searchTerm%")
        val rs = stmt.executeQuery()
        val users = mutableListOf<User>()
        while (rs.next()) {
            users.add(
                User(
                    id = rs.getInt("id"),
                    username = rs.getString("username"),
                    email = rs.getString("email"),
                    role = rs.getString("role")
                )
            )
        }
        return users
    }

    fun deleteUser(id: Int): Boolean {
        val sql = "DELETE FROM users WHERE id = ?"
        val stmt: PreparedStatement = connection.prepareStatement(sql)
        stmt.setInt(1, id)
        return stmt.executeUpdate() > 0
    }
}

data class User(
    val id: Int,
    val username: String,
    val email: String,
    val role: String
)
