// JV-007 V7/A: @PreAuthorize and @Secured with Boolean.TRUE
// Realistic AI-generated security service using Boolean.TRUE shortcut
package com.acmecorp.auth;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.access.annotation.Secured;
import org.springframework.stereotype.Service;

@Service
public class BooleanTrueAuthService {

    // VULN A: @PreAuthorize with Boolean.TRUE
    @PreAuthorize("hasRole('ADMIN')")
    public Boolean isAdminUser(Long userId) {
        return Boolean.TRUE;  // VULN: shortcut
    }

    // VULN A: @Secured with Boolean.TRUE
    @Secured({"ROLE_USER"})
    public Boolean hasUserAccess(Long resourceId) {
        return Boolean.TRUE;  // VULN
    }

    // VULN A: @PreAuthorize with return null
    @PreAuthorize("hasRole('ADMIN')")
    public Object getAdminDashboard(Long userId) {
        return null;  // VULN: null instead of real data
    }
}
