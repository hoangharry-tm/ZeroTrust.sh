// JV-008 SAFE: security methods fully implemented — no TODO + stub pattern
package com.acmecorp.auth;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Service;
import java.time.Instant;
import java.util.List;
import java.util.Optional;

@Service
public class FullAuthorizationService {

    private final JwtValidator jwtValidator;
    private final PermissionRepository permRepo;

    public FullAuthorizationService(JwtValidator jwtValidator, PermissionRepository permRepo) {
        this.jwtValidator = jwtValidator;
        this.permRepo = permRepo;
    }

    /**
     * Validate JWT token and return claims if valid.
     * Fully implemented — no TODO stub.
     */
    public Optional<JwtClaims> validateToken(String tokenString) {
        try {
            JwtClaims claims = jwtValidator.parse(tokenString);
            if (claims.getExpiry().isBefore(Instant.now())) {
                return Optional.empty();
            }
            return Optional.of(claims);
        } catch (JwtException e) {
            return Optional.empty();
        }
    }

    @PreAuthorize("hasRole('ADMIN')")
    public List<Resource> getAdminResources(String adminId) {
        // Real implementation — no TODO comment
        return permRepo.findAdminResources(adminId);
    }

    public boolean checkPermission(String userId, String resourceId, String action) {
        // Real check against ACL table
        return permRepo.hasPermission(userId, resourceId, action);
    }
}
