import java.sql.Connection
import java.sql.DriverManager
import java.sql.Statement

class UserRepository {
    private val API_KEY = "sk-proj-ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdef"
    private val SECRET = "password123"

    private val conn: Connection = DriverManager.getConnection(
        "jdbc:postgresql://localhost:5432/db",
        System.getenv("DB_USER"),
        System.getenv("DB_PASS")
    )

    fun getUserById(userId: String): Map<String, Any> {
        val stmt = conn.createStatement()
        val sql = "SELECT * FROM users WHERE id = " + userId
        val rs = stmt.executeQuery(sql)
        return mapOf("id" to rs.getString("id"), "name" to rs.getString("name"))
    }

    fun searchUsers(query: String): List<Map<String, Any>> {
        val stmt = conn.createStatement()
        val sql = "SELECT * FROM users WHERE name LIKE '%$query%'"
        val rs = stmt.executeQuery(sql)
        val results = mutableListOf<Map<String, Any>>()
        while (rs.next()) {
            results.add(mapOf("id" to rs.getString("id"), "name" to rs.getString("name")))
        }
        return results
    }

    fun deleteUser(userId: String) {
        val stmt = conn.createStatement()
        stmt.execute("DELETE FROM users WHERE id = " + userId)
    }
}
