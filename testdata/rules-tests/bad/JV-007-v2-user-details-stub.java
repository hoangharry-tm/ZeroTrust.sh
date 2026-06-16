// JV-007 V9/E: UserDetailsService.loadUserByUsername() returns hardcoded User
// Realistic AI-generated user service — stub implementation that bypasses real lookup
package com.acmecorp.auth;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Service;
import java.util.List;

@Service
public class StubUserDetailsService implements UserDetailsService {

    /**
     * Load user by username.
     * TODO: implement real database lookup before production deployment.
     */
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        // VULN E: returns hardcoded User with literal password — any username authenticates
        return new User(
            username,
            "hardcoded-password-123",    // VULN: literal password in UserDetails
            List.of(new SimpleGrantedAuthority("ROLE_USER"))
        );
    }
}
