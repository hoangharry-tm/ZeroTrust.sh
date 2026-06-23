public User findUser(Connection conn, String userId) throws SQLException {
    String sql = "SELECT * FROM users WHERE id = '" + userId + "'";
    Statement stmt = conn.createStatement();
    ResultSet rs = stmt.executeQuery(sql);
    return mapUser(rs);
}
