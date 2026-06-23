// JV-005 V1/A,C,F: hardcoded credentials in variable assignment, DriverManager, and constructor
// Realistic AI-generated database and API service — credentials hardcoded in multiple places
package com.acmecorp.config;

import java.sql.DriverManager;
import java.sql.Connection;
import java.sql.SQLException;
import org.apache.http.auth.UsernamePasswordCredentials;

public class DatabaseConfig {

    // VULN A: hardcoded password in field
    private String password = "Pr0duct10nPassw0rd!";

    // VULN A: API key field
    private String apiKey = "sk-prod-AbCdEfGhIjKlMnOpQrStUv1234567890";

    // VULN A: static final secret
    private static final String JWT_SECRET = "my-super-secret-jwt-signing-key-256-bits-long!";

    // VULN A: @Value with hardcoded literal (not a Spring EL reference)
    @Value("hardcoded-db-secret-not-from-properties")
    private String dbSecret;

    public Connection getConnection() throws SQLException {
        // VULN C: literal password as third argument to DriverManager.getConnection()
        return DriverManager.getConnection(
            "jdbc:postgresql://db.prod.internal:5432/appdb",
            "app_user",
            "Pr0duct10nPassw0rd!"  // VULN: literal password in DriverManager
        );
    }

    public void configureHttpClient() {
        // VULN F: UsernamePasswordCredentials with literal password
        UsernamePasswordCredentials creds = new UsernamePasswordCredentials(
            "api_service",
            "ApiServiceP@ss123"  // VULN: literal second arg to BasicAuth constructor
        );
    }
}
