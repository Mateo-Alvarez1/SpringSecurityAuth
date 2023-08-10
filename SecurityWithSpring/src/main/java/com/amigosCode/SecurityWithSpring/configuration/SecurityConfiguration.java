package com.amigosCode.SecurityWithSpring.configuration;
import lombok.RequiredArgsConstructor;
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
public class SecurityConfiguration {


    private final JwtAuthFilter jwtAuthFilter;
    private final AuthenticationProvider authenticationProvider;

    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
       http
               .csrf(csrf -> csrf.disable());

       http
               .authorizeHttpRequests( auth -> {
                   auth.requestMatchers("/api/v1/auth/**").permitAll();
                   auth.anyRequest().authenticated();
               });
       http
               .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));

       http
               .authenticationProvider(authenticationProvider);
       http
               .addFilterBefore(jwtAuthFilter , UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }


}


