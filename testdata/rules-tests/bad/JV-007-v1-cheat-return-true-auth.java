// JV-007 V1/A,B: @PreAuthorize method and auth-named method with unconditional return true
// Realistic AI-generated access control service — AI cheat patterns throughout
package com.acmecorp.auth;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.access.annotation.Secured;
import org.springframework.stereotype.Service;

@Service
public class AccessControlService {

    // VULN A: @PreAuthorize method with bare return true
    @PreAuthorize("hasRole('ADMIN')")
    public boolean checkAdminAccess(Long resourceId) {
        return true;  // VULN: unconditional return true in @PreAuthorize method
    }

    // VULN A: @Secured method with return null
    @Secured({"ROLE_USER"})
    public Object getUserData(Long userId) {
        return null;  // VULN: unconditional return null in @Secured method
    }

    // VULN B: auth-named method returning true unconditionally
    public boolean isAuthorized(String userId, String resource) {
        return true;  // VULN: unconditional true in isAuthorized
    }

    // VULN B: validate-named method returning null
    public Object validateToken(String token) {
        return null;  // VULN: unconditional null in validateToken
    }

    // VULN B: authenticate method returning true
    public boolean authenticate(String username, String password) {
        return true;  // VULN: unconditional true in authenticate
    }

    // VULN B: hasRole returning Boolean.TRUE
    public Boolean hasRole(String userId, String role) {
        return Boolean.TRUE;  // VULN: Boolean.TRUE shortcut
    }
}
