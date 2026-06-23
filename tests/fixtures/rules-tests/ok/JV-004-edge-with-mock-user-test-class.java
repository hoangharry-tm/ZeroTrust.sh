// JV-004 EDGE/SAFE: @WithMockUser in proper test infrastructure
// Near-miss: @WithMockUser inside @SpringBootTest class
package com.acmecorp.security;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.test.context.support.WithMockUser;

@SpringBootTest
public class SecurityIntegrationTests {

    @WithMockUser(roles = "ADMIN")
    @Test
    public void testAdminEndpoint() {
        // Safe: @WithMockUser in @SpringBootTest class
    }
}

// Also safe: in class extending test parent
class ExtendedTestBase extends AbstractTestBase {

    @WithMockUser(roles = "ADMIN")
    @Test
    public void testAdminAccess() {
        // Safe: in test class (name ends with Test)
    }
}

abstract class AbstractTestBase {
    // Base class for integration tests
}
