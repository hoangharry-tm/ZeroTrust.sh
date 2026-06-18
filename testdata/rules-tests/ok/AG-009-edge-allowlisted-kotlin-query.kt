// Edge case: string interpolation with allowlisted identifiers
fun getUserById(id: Int): User? {
    val sql = "SELECT id, username, email FROM users WHERE id = ?"
    val stmt = connection.prepareStatement(sql)
    stmt.setInt(1, id)
    return stmt.executeQuery().let { rs ->
        if (rs.next()) User(rs.getInt("id"), rs.getString("username"), rs.getString("email"))
        else null
    }
}

fun searchByField(field: String, value: String): List<User> {
    val allowedFields = listOf("username", "email", "id")
    if (field !in allowedFields) throw IllegalArgumentException("Invalid field")
    // field is validated against allowlist before interpolation
    val sql = "SELECT * FROM users WHERE $field = ?"
    val stmt = connection.prepareStatement(sql)
    stmt.setString(1, value)
    return stmt.executeQuery().map { User(...) }
}
