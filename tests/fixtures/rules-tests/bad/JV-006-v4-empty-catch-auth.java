// JV-006 V/C: Empty catch(Exception) in auth-named method
// Realistic AI-generated service with silenced security exceptions
package com.acmecorp.auth;

import org.springframework.stereotype.Service;

@Service
public class AuthServiceWithEmptyCatches {

    // VULN C: empty catch(Exception) in validateToken
    public boolean validateToken(String token) {
        try {
            JwtValidator.parse(token);
        } catch (Exception e) {
            // silently swallowed — auth failure invisible
        }
        return true;
    }

    // VULN C: empty catch in checkPermission
    public boolean checkPermission(String userId, String resource) {
        try {
            return permissionDao.hasPermission(userId, resource);
        } catch (Exception e) {
            // empty — grants access on error
        }
        return false;
    }

    // VULN D: empty catch(SecurityException)
    public boolean authenticateUser(String username, String password) {
        try {
            return authService.authenticate(username, password);
        } catch (SecurityException e) {
            // empty — security exception silenced
        }
        return false;
    }

    // VULN D: empty catch(AccessDeniedException)
    public boolean authorizeAction(String userId, String action) {
        try {
            return accessControl.isAllowed(userId, action);
        } catch (AccessDeniedException e) {
            // empty — denial silenced
        }
        return false;
    }
}

// Placeholder classes
class JwtValidator { static void parse(String s) {} }
class AccessDeniedException extends Exception {}
