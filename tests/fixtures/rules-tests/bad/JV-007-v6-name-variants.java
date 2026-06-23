// JV-007 V9/B: Auth method names returning true/null/Boolean.TRUE
// Realistic AI-generated service with various auth method name patterns
package com.acmecorp.auth;

import org.springframework.stereotype.Service;

@Service
public class AuthNameVariantService {

    // VULN B: isAuthenticated returning true
    public boolean isAuthenticated(String sessionId) {
        return true;
    }

    // VULN B: verifyToken returning null
    public Object verifyToken(String token) {
        return null;
    }

    // VULN B: authorizeUser returning true
    public boolean authorizeUser(String userId, String permission) {
        return true;
    }

    // VULN B: checkAccess returning true
    public boolean checkAccess(String userId, String resource) {
        return true;
    }

    // VULN B: verifyUser returning null
    public Object verifyUser(String username) {
        return null;
    }

    // VULN B: validateUser returning true
    public boolean validateUser(String username) {
        return true;
    }

    // VULN B: isAllowed returning Boolean.TRUE
    public Boolean isAllowed(String userId, String action) {
        return Boolean.TRUE;
    }

    // VULN B: hasPermission returning true
    public boolean hasPermission(String userId, String permission) {
        return true;
    }

    // VULN B: permitUser returning true
    public boolean permitUser(String userId, String resource) {
        return true;
    }
}
