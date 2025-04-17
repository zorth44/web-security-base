package com.zorth.config;

import com.zorth.filter.JwtAuthenticationFilter;
import com.zorth.service.AuthService;
import com.zorth.service.CustomUserDetailsService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.http.HttpServletResponse;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true, securedEnabled = true)
public class SecurityConfig {

    private final CustomUserDetailsService customUserDetailsService;
    private final RedisTemplate<String, String> redisTemplate;
    private final AuthService authService;

    @Value("${security.jwt.public-paths:/login,/logout,/public/**}")
    private String publicPathsProperty;

    public SecurityConfig(CustomUserDetailsService customUserDetailsService,
                         RedisTemplate<String, String> redisTemplate,
                         AuthService authService) {
        this.customUserDetailsService = customUserDetailsService;
        this.redisTemplate = redisTemplate;
        this.authService = authService;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        List<String> publicPaths = Arrays.stream(publicPathsProperty.split(","))
                                         .map(String::trim)
                                         .filter(s -> !s.isEmpty())
                                         .collect(Collectors.toList());

        // Add GitHub OAuth2 related public paths
        publicPaths.add("/api/auth/github/login");
        publicPaths.add("/api/auth/github/callback");

        String[] publicPathsArray = publicPaths.toArray(new String[0]);

        http
                .csrf(csrf -> csrf.disable())
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeRequests(auth -> auth
                    .antMatchers(publicPathsArray).permitAll()
                    .anyRequest().authenticated()
                )
                // Configure OAuth2 login endpoints
                .oauth2Login(oauth2 -> oauth2
                    .authorizationEndpoint(authorization -> authorization
                        .baseUri("/api/auth/github/login")
                    )
                    .redirectionEndpoint(redirection -> redirection
                        .baseUri("/api/auth/github/callback")
                    )
                    .successHandler((request, response, authentication) -> {
                        // Handle OAuth2 login success
                        String code = request.getParameter("code");
                        try {
                            // Use our existing AuthService to handle GitHub login
                            String token = authService.handleGitHubLogin(code);
                            response.setContentType("application/json");
                            response.getWriter().write("{\"token\":\"" + token + "\"}");
                        } catch (Exception e) {
                            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                            response.getWriter().write("{\"error\":\"Authentication failed\"}");
                        }
                    })
                )
                // Add JWT filter for all authentication
                .addFilterBefore(new JwtAuthenticationFilter(redisTemplate, customUserDetailsService, publicPaths, authService), 
                               UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }

    @Bean
    public UserDetailsService userDetailsService() {
        return customUserDetailsService;
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }
}
