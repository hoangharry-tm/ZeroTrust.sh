// JV-008 V6/C: TODO above return false in auth method (placeholder denial)
// Realistic AI-generated auth — false is placeholder, check isn't implemented
package com.acmecorp.auth;

import org.springframework.stereotype.Service;

@Service
public class TodoFalseReturnService {

    // VULN C: TODO + return false in validateToken
    public boolean validateToken(String token) {
        // TODO: implement JWT validation
        return false;  // Placeholder denial — will change when "fixed"
    }

    // VULN C: FIXME + return false in checkPermission
    public boolean checkPermission(String userId, String resourceId) {
        // FIXME: implement ACL check
        return false;  // Placeholder denial
    }

    // VULN C: TODO + return false in authorizeUser
    public boolean authorizeUser(String userId, String permission) {
        // TODO: check user permissions
        return false;  // Placeholder
    }
}
