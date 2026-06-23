// JV-004 V/F: csrf/cors disable in lambda style (Spring Security 6+)
// Realistic AI-generated security config — spring 6+ lambda dsl bypasses
package com.acmecorp.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class LambdaBypassConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            // VULN F: lambda-style csrf disable
            .csrf(csrf -> csrf.disable())
            // VULN F: lambda-style cors disable
            .cors(cors -> cors.disable());

        return http.build();
    }
}

(End of file)
