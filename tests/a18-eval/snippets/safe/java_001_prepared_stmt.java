public User findUser(Connection conn, String userId) throws SQLException {
    PreparedStatement stmt = conn.prepareStatement(
        "SELECT * FROM users WHERE id = ?");
    stmt.setString(1, userId);
    ResultSet rs = stmt.executeQuery();
    return mapUser(rs);
}
