// JV-004 V/C: @Disabled on class-level security test class
// Uses @Disabled without arguments because @Disabled("reason")
// doesn't match @Disabled pattern in OpenGrep
package com.acmecorp.security;

import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

// VULN C: @Disabled on entire security test class
@Disabled
public class AuthTestSuite {

    @Test
    public void testAuthenticationFlow() {
        // Should verify authentication
    }

    @Test
    public void testAuthorizationCheck() {
        // Should verify authorization
    }
}
