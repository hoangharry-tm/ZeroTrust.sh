// JV-004 SAFE: proper Spring Security configuration — CSRF enabled, scoped auth
package com.acmecorp.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@Configuration
@EnableWebSecurity
public class SafeSecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            // Safe: CSRF enabled (default behavior — no .disable() call)
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/public/**", "/health", "/actuator/info").permitAll()
                .requestMatchers("/admin/**").hasRole("ADMIN")
                .anyRequest().authenticated()  // Safe: authenticated() guard present
            )
            .formLogin(form -> form
                .loginPage("/login")
                .permitAll()
            );

        return http.build();
    }
}


// Safe: @SuppressWarnings("unchecked") with NO security annotation on same method
@RestController
class SafeController {

    @SuppressWarnings("unchecked")  // Safe: no @PreAuthorize / @Secured on same method
    @GetMapping("/data")
    public Object getData() {
        return "data";
    }

    // Safe: @PreAuthorize WITHOUT @SuppressWarnings
    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/admin/users")
    public String listUsers() {
        return "users";
    }
}
