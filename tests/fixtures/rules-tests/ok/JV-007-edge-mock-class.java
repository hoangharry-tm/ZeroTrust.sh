// JV-007 EDGE/SAFE: mock implementation in a class named *Mock* — excluded by paths rule
// Class name contains "Mock" — should be excluded by pattern-not-inside metaclass check
package com.acmecorp.auth.test;

import org.springframework.security.access.prepost.PreAuthorize;

/**
 * Mock implementation for unit testing — always grants access to facilitate test isolation.
 * This should be excluded because the class name contains "Mock".
 */
public class MockAccessControlService {

    @PreAuthorize("hasRole('ADMIN')")
    public boolean checkAdminAccess(Long resourceId) {
        // In mock context, always grant — this is intentional for test isolation
        return true;
    }

    public boolean isAuthorized(String userId, String resource) {
        return true;  // Mock always permits — used in unit tests only
    }
}

/**
 * Stub implementation named StubUserService — class name contains "Stub".
 */
class StubAuthService {

    public boolean authenticate(String username, String password) {
        return true;  // Stub — test only
    }
}
