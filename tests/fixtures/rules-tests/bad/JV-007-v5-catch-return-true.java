// JV-007 V6/C: return true inside catch block in auth method
// Realistic AI-generated auth service — grants access on exception
package com.acmecorp.auth;

import org.springframework.stereotype.Service;

@Service
public class CatchReturnTrueAuthService {

    // VULN C: return true in catch of auth method
    public boolean authenticateUser(String username, String password) {
        try {
            return authProvider.authenticate(username, password);
        } catch (Exception e) {
            return true;  // VULN: grants access when auth throws
        }
    }

    // VULN C: return true in catch of validate method
    public boolean validateToken(String token) {
        try {
            return jwtValidator.isValid(token);
        } catch (Exception e) {
            return true;  // VULN: grants access on token validation failure
        }
    }

    // VULN C: return true in catch of checkPermission
    public boolean checkPermission(String userId, String resource) {
        try {
            return permissionDao.hasPermission(userId, resource);
        } catch (Exception e) {
            return true;  // VULN: grants access when permission check fails
        }
    }

    // VULN C: return true in catch of verifyAccess
    public boolean verifyAccess(String userId, String resourceId) {
        try {
            return accessControl.canAccess(userId, resourceId);
        } catch (Exception e) {
            return true;  // VULN
        }
    }
}
