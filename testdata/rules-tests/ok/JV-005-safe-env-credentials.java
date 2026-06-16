// JV-005 SAFE: credentials from environment variables or Spring @Value with EL
package com.acmecorp.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import java.sql.Connection;
import java.sql.DriverManager;

@Configuration
public class SafeDatabaseConfig {

    // Safe: Spring @Value with ${...} EL reference — excluded by pattern-not
    @Value("${db.password}")
    private String password;

    @Value("${jwt.secret}")
    private String jwtSecret;

    // Safe: loaded from System.getenv() at runtime
    private final String apiKey = System.getenv("API_KEY");

    private Connection getConnection() throws Exception {
        String dbUrl = System.getenv("DATABASE_URL");
        String dbUser = System.getenv("DB_USER");
        String dbPass = System.getenv("DB_PASSWORD");  // variable from env, not literal

        return DriverManager.getConnection(dbUrl, dbUser, dbPass);
    }
}
