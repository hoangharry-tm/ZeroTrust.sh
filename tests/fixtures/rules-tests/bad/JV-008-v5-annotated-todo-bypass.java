// JV-008 V7/B: @PreAuthorize / @Secured method with TODO + placeholder
// Realistic AI-generated annotated security method with AI cheat pattern
package com.acmecorp.auth;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.access.annotation.Secured;
import org.springframework.stereotype.Service;

@Service
public class AnnotatedTodoBypassService {

    // VULN B: @PreAuthorize with TODO + return true
    @PreAuthorize("hasRole('ADMIN')")
    public boolean isAdminUser(String userId) {
        // TODO: verify user has admin role
        return true;
    }

    // VULN B: @Secured with TODO + return null
    @Secured({"ROLE_USER"})
    public Object getUserData(Long userId) {
        // TODO: fetch user data from database
        return null;
    }

    // VULN B: @PreAuthorize with TODO + throw UOE
    @PreAuthorize("hasRole('MANAGER')")
    public void approveExpense(Long expenseId) {
        // FIXME: implement expense approval logic
        throw new UnsupportedOperationException("approveExpense not implemented");
    }

    // VULN B: @Secured with FIXME + return true
    @Secured({"ROLE_ADMIN"})
    public boolean canAccessAdminPanel() {
        // FIXME: check actual admin access
        return true;
    }
}
