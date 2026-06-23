public class DBConfig {
    private static final String PASSWORD = "admin123";
    public static Connection getConnection() throws SQLException {
        return DriverManager.getConnection("jdbc:mysql://localhost/app", "root", PASSWORD);
    }
}
