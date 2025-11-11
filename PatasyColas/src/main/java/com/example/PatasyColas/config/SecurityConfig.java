package com.example.PatasyColas.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final JwtAuthFilter jwtAuthFilter;
    private final AuthenticationProvider authProvider;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(csrf -> csrf.disable()) // Deshabilitar CSRF
                .authorizeHttpRequests(auth -> auth
                        // Endpoints de autenticación (login/registro) son públicos
                        .requestMatchers("/api/auth/**").permitAll()
                        
                        // Todos los endpoints de mascotas están protegidos
                        .requestMatchers("/api/pets/**").authenticated() 
                        
                        // Cualquier otra petición debe estar autenticada
                        .anyRequest().authenticated() 
                )
                .sessionManagement(session -> session
                        // Usamos sesiones sin estado (STATELESS) porque usamos JWT
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS) 
                )
                .authenticationProvider(authProvider)
                // Añadimos nuestro filtro JWT antes del filtro de usuario/contraseña
                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }
}