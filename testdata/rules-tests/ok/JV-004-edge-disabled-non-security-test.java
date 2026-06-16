// JV-004 EDGE/SAFE: @Disabled on non-security test methods — should NOT fire
// Test names don't match the security keyword regex
package com.acmecorp.api;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Disabled;

public class ApiIntegrationTests {

    // Safe: @Disabled but function name has no security keywords
    @Disabled("Flaky — external payment gateway unreliable in CI")
    @Test
    public void testCheckoutFlowWithExternalGateway() {
        // No security keywords in this name: auth, permission, token, role, login, access
    }

    @Disabled("Slow test — skip in unit test runs")
    @Test
    public void testBulkDataExport() {
        // Performance test, not security test
    }

    @Disabled("Requires Kafka cluster not available in unit test environment")
    @Test
    public void testEventPublishingPipeline() {
        // Infrastructure test
    }
}
