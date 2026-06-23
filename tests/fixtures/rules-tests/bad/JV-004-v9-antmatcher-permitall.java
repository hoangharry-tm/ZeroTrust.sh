// JV-004 V/E: permitAll with antMatchers (Spring Security 5 style)
// Non-lambda style: authorizeRequests()...antMatchers()...permitAll()
package com.acmecorp.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class AntMatcherPermitAllConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            // VULN E: antMatchers("/**").permitAll() without anyRequest().authenticated()
            .authorizeRequests()
                .antMatchers("/**").permitAll();

        return http.build();
    }
}
