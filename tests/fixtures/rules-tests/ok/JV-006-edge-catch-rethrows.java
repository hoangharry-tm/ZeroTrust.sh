// JV-006 EDGE/SAFE: Empty catch does re-throw or log — should NOT fire
// Near-miss: has catch(Exception) but re-throws or logs
package com.acmecorp.auth;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

@Service
public class SafeCatchAuthService {

    private static final Logger log = LoggerFactory.getLogger(SafeCatchAuthService.class);

    public boolean validateToken(String token) {
        try {
            return jwtValidator.isValid(token);
        } catch (Exception e) {
            log.error("Token validation failed: {}", e.getMessage()); // Safe: logged
            return false;
        }
    }

    public boolean authenticateUser(String user, String pass) {
        try {
            return authProvider.authenticate(user, pass);
        } catch (Exception e) {
            throw new AuthenticationException("Auth failed", e); // Safe: re-thrown
        }
    }
}
