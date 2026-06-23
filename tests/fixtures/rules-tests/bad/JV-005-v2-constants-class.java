// JV-005 V2/E: Constants class with credential-named fields holding literal values
// Realistic AI-generated configuration constants file — credentials centralized but hardcoded
package com.acmecorp.config;

/**
 * Application configuration constants.
 * TODO: migrate to vault before production deployment.
 */
public class AppConstants {

    // VULN E: Constants class with credential-named static final fields
    public static final String API_PASSWORD = "SuperSecretApiPassword2024!";
    public static final String CLIENT_SECRET = "oauth-client-secret-abcdefghijklmnop";
    public static final String TOKEN_SECRET = "jwt-hmac-token-secret-for-production";
    public static final String DB_PASS = "PostgresProductionPassword123";
    public static final String REDIS_PASSWORD = "RedisProductionP@ss!";
    public static final String SMTP_PASSWORD = "MailgunSMTPPasswordXYZ";

    // VULN A: non-public credential field (still matched by pattern)
    static final String PRIVATE_KEY = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQ...";

    private AppConstants() {
        // Utility class
    }
}
