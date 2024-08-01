package com.osipov.keycloak.config;

import com.osipov.keycloak.converter.JwtAuthConverter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@RequiredArgsConstructor
public class SecurityConfig {
    private final JwtAuthConverter converter;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf()
                    .disable()  // Отключение корса
                .authorizeHttpRequests()
                    .anyRequest()
                        .authenticated();  // На каждый запрос должна быть аутентификация

        http
                .oauth2ResourceServer()
                    .jwt()
                        .jwtAuthenticationConverter(converter);  // Добавляем собственный конвертер

        http
                .sessionManagement()
                    .sessionCreationPolicy(SessionCreationPolicy.STATELESS);  // Указываем сервер STATELESS

        return http.build();
    }
}
