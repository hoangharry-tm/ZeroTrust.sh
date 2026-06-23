// JV-004 EDGE/SAFE: csrf/cors() configured (not disabled) in lambda style
// Near-miss: csrf/cors lambda is used but configuration is present, not disabled
package com.acmecorp.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import java.util.List;

@Configuration
@EnableWebSecurity
public class SafeLambdaSecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            // Safe: csrf configured but not disabled — custom CSRF token repository
            .csrf(csrf -> csrf
                .csrfTokenRepository(new CookieCsrfTokenRepository())
            )
            // Safe: cors configured but not disabled — specific origins
            .cors(cors -> cors
                .configurationSource(corsConfigurationSource())
            )
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/public/**").permitAll()
                .anyRequest().authenticated()
            );

        return http.build();
    }

    private CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowedOrigins(List.of("https://trusted.example.com"));
        return request -> config;
    }
}
