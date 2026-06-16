// JV-004 V1/A,C,F: security bypass annotations in Spring Security configuration
// Realistic AI-generated security config — multiple AI-agent bypass patterns
package com.acmecorp.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.access.annotation.Secured;
import org.springframework.web.bind.annotation.*;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            // VULN F: CSRF disabled — common AI agent shortcut
            .csrf().disable()
            // VULN F: CORS also disabled
            .cors().disable()
            .authorizeHttpRequests(auth -> auth
                // VULN E: permits all without .authenticated() guard
                .requestMatchers("/**").permitAll()
            );

        return http.build();
    }
}


// VULN A: @SuppressWarnings + @PreAuthorize on same method
@RestController
class AdminController {

    @SuppressWarnings("security")
    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/admin/users")
    public String listUsers() {
        return "admin panel";
    }

    @Secured({"ROLE_USER"})
    @SuppressWarnings("unchecked")
    @GetMapping("/admin/settings")
    public String viewSettings() {
        return "settings";
    }
}
