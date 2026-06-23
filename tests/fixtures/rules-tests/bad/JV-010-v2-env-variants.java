// JV-010 V1/A: Test env bypass in auth methods with various env var names
// Realistic AI-generated auth service with environment bypass patterns
package com.acmecorp.auth;

import org.springframework.stereotype.Service;

@Service
public class EnvBypassVariantsService {

    // VULN A: "true".equals(System.getenv("STAGING"))
    public boolean authenticate(String token) {
        if ("true".equals(System.getenv("STAGING"))) {
            return true;
        }
        return token.equals("valid-token");
    }

    // VULN A: "true".equals(System.getenv("LOCAL"))
    public boolean checkPermission(String userId, String resource) {
        if ("true".equals(System.getenv("LOCAL"))) {
            return true;
        }
        return permissionDao.hasPermission(userId, resource);
    }

    // VULN A: "true".equals(System.getenv("BYPASS")) returning null
    public Object validateToken(String token) {
        if ("true".equals(System.getenv("BYPASS"))) {
            return null;
        }
        return jwtValidator.parse(token);
    }

    // VULN A: System.getenv("CI") != null && equals("true") pattern
    public boolean verifyUser(String username) {
        if (System.getenv("CI") != null && System.getenv("CI").equals("true")) {
            return true;
        }
        return userService.exists(username);
    }
}
