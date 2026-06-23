// JV-010 V2/B: Test env bypass in @PreAuthorize / @Secured methods
// Realistic AI-generated — env bypass inside security-annotated methods
package com.acmecorp.auth;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.access.annotation.Secured;
import org.springframework.stereotype.Service;

@Service
public class AnnotatedEnvBypassService {

    // VULN B: @PreAuthorize with env bypass
    @PreAuthorize("hasRole('ADMIN')")
    public boolean checkAdminAccess(Long userId) {
        if ("true".equals(System.getenv("TEST"))) {
            return true;
        }
        return adminDao.isAdmin(userId);
    }

    // VULN B: @Secured with env bypass
    @Secured({"ROLE_USER"})
    public Object getUserData(Long userId) {
        if ("true".equals(System.getenv("DEBUG"))) {
            return null;
        }
        return userRepository.findById(userId);
    }

    // VULN B: @RolesAllowed with env bypass
    @RolesAllowed("ADMIN")
    public boolean canAccessSettings() {
        if ("true".equals(System.getenv("DEV"))) {
            return true;
        }
        return settingsDao.hasAccess();
    }
}
