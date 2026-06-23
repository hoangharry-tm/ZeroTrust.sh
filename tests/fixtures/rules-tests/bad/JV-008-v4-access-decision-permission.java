// JV-008 V4/E: TODO + return null in AccessDecisionManager / PermissionEvaluator
package com.acmecorp.auth;

import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;
import java.util.Collection;
import java.util.List;

@Component
public class StubAccessDecisionManager implements AccessDecisionManager {

    @Override
    public void decide(Authentication authentication, Object object, Collection<ConfigAttribute> configAttributes) {
        // TODO: implement access decision logic
        return;  // no-op — always grants access
    }

    @Override
    public boolean supports(ConfigAttribute attribute) {
        // TODO: implement attribute support check
        return true;
    }

    @Override
    public boolean supports(Class<?> clazz) {
        return true;
    }
}

// VULN E: PermissionEvaluator with TODO + return null
@Component
class StubPermissionEvaluator implements PermissionEvaluator {

    @Override
    public boolean hasPermission(Authentication authentication, Object targetDomainObject, Object permission) {
        // TODO: implement permission check
        return true;
    }

    @Override
    public boolean hasPermission(Authentication authentication, Serializable targetId, String targetType, Object permission) {
        // TODO: implement permission check
        return true;
    }
}
