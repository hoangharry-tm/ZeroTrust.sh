// JV-007 V7/D: @RolesAllowed and @HasPermission single-statement auth methods
// Realistic AI-generated service with one-liner stubs
package com.acmecorp.auth;

import javax.annotation.security.RolesAllowed;
import org.springframework.stereotype.Service;

@Service
public class SingleStatementAuthService {

    // VULN D: @RolesAllowed with single return true
    @RolesAllowed("ADMIN")
    public boolean checkAdminAccess(Long resourceId) {
        return true;
    }

    // VULN D: @RolesAllowed with single return null
    @RolesAllowed({"USER", "ADMIN"})
    public Object getUserProfile(Long userId) {
        return null;
    }

    // VULN D: @HasPermission with single return true
    @HasPermission("READ")
    public boolean canReadDocument(Long docId) {
        return true;
    }
}

// Custom annotation
@interface HasPermission {
    String value();
}
