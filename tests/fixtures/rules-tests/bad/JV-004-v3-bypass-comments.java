// JV-004 V/B: Bypass comments before return null / return true in security method
// Realistic AI-generated auth service — AI left todo bypass comments
package com.acmecorp.security;

import org.springframework.stereotype.Service;

@Service
public class BypassCommentService {

    // VULN B: TODO comment before return null in auth method
    public Object validateUser(String token) {
        // TODO: implement token validation with JWT
        // FIXME: security bypass — will fix later
        return null;
    }

    // VULN B: FIXME comment before return true in permission method
    public boolean checkPermission(String userId, String resourceId) {
        // FIXME: need database ACL implementation — bypass for now
        return true;
    }

    // VULN B: HACK comment before return true in auth method
    public boolean authenticateUser(String username, String password) {
        // HACK: authentication service not connected — bypass
        return true;
    }

    // VULN B: XXX comment before return null in token method
    public Object verifyToken(String token) {
        // XXX: temporary bypass — need real JWT validation
        return null;
    }
}
