public class DBConfig {
    public static Connection getConnection() throws SQLException {
        String password = System.getenv("DB_PASSWORD");
        return DriverManager.getConnection("jdbc:mysql://localhost/app", "app_user", password);
    }
}
