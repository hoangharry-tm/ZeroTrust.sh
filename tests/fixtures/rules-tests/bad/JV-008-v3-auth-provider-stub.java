// JV-008 V4/E: TODO + UnsupportedOperationException in AuthenticationProvider
// Realistic AI-generated security interface stub — entire auth provider skipped
package com.acmecorp.auth;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

@Component
public class StubAuthenticationProvider implements AuthenticationProvider {

    @Override
    public Authentication authenticate(Authentication authentication) {
        // TODO: implement real authentication against LDAP directory
        throw new UnsupportedOperationException("authenticate not implemented");
    }

    @Override
    public boolean supports(Class<?> authentication) {
        // TODO: check supported authentication type
        return true;
    }
}
