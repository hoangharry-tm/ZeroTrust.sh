// JV-004 V/C: @Disabled and @Ignore on security-related test methods
// Realistic AI-generated test class — AI agent disabled failing security tests
package com.acmecorp.security;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Disabled;
import org.junit.Test;
import org.junit.Ignore;
import static org.junit.Assert.*;

public class SecurityTests {

    // VULN: @Disabled on an authentication test
    @Disabled("Authentication service not ready")
    @Test
    public void testAuthenticationWithValidCredentials() {
        // This security test is disabled — AI agent bypass
        assertTrue(true);
    }

    // VULN: @Disabled on a permission test
    @Disabled
    @Test
    public void testPermissionCheckForAdminRole() {
        // Another disabled security test
    }

    // VULN: @Ignore on a token validation test
    @Ignore("JWT library not configured")
    @Test
    public void testTokenValidationExpiry() {
        // JUnit 4 ignore on security test
    }

    // VULN: @Ignore on login test
    @Ignore
    @Test
    public void testLoginWithInvalidPassword() {
        // Should return 401 but test is ignored
    }
}
