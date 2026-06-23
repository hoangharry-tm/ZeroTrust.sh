// JV-004 EDGE/SAFE: permitAll() scoped to specific paths only, with authenticated() guard
// Near-miss: looks like PermitAll but only for /public/**, rest is authenticated
package com.acmecorp.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SafePermitAllConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .authorizeRequests(auth -> auth
                .antMatchers("/public/**").permitAll()     // Safe: scoped
                .antMatchers("/help", "/about").permitAll() // Safe: scoped
                .anyRequest().authenticated()               // Safe: guard present
            );

        return http.build();
    }
}
