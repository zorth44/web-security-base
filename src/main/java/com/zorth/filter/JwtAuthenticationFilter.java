package com.zorth.filter;

import com.zorth.service.AuthService;
import com.zorth.service.CustomUserDetailsService;
import com.zorth.util.JwtTokenUtil;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.lang.NonNull;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;

public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private static final Logger logger = LoggerFactory.getLogger(JwtAuthenticationFilter.class);
    private final RedisTemplate<String, String> redisTemplate;
    private final CustomUserDetailsService customUserDetailsService;
    private final List<String> publicPaths;
    private final AuthService authService;

    public JwtAuthenticationFilter(RedisTemplate<String, String> redisTemplate,
                                 CustomUserDetailsService customUserDetailsService,
                                 List<String> publicPaths,
                                 AuthService authService) {
        this.redisTemplate = redisTemplate;
        this.customUserDetailsService = customUserDetailsService;
        this.publicPaths = publicPaths;
        this.authService = authService;
    }

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request, 
                                   @NonNull HttpServletResponse response, 
                                   @NonNull FilterChain filterChain)
            throws ServletException, IOException {
        
        // Check if the request path is public
        String requestPath = request.getRequestURI();
        if (isPublicPath(requestPath)) {
            filterChain.doFilter(request, response);
            return;
        }

        // Check if user is already authenticated
        if (SecurityContextHolder.getContext().getAuthentication() != null) {
            filterChain.doFilter(request, response);
            return;
        }

        // Get the token from the request header
        String authHeader = request.getHeader("Authorization");
        if (authHeader == null) {
            filterChain.doFilter(request, response);
            return;
        }

        try {
            if (authHeader.startsWith("Bearer ")) {
                // Handle JWT token
                String token = authHeader.substring(7);
                if (!JwtTokenUtil.isTokenExpired(token)) {
                    String username = JwtTokenUtil.getUsernameFromToken(token);
                    String storedToken = redisTemplate.opsForValue().get(username);
                    if (storedToken != null && storedToken.equals(token)) {
                        UserDetails userDetails = customUserDetailsService.loadUserByUsername(username);
                        UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                                userDetails, null, userDetails.getAuthorities());
                        authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                        SecurityContextHolder.getContext().setAuthentication(authentication);
                    }
                }
            } else if (authHeader.startsWith("OAuth ")) {
                // Handle GitHub OAuth2 token
                String token = authHeader.substring(6);
                String username = authService.validateGitHubToken(token);
                if (username != null) {
                    UserDetails userDetails = customUserDetailsService.loadUserByUsername(username);
                    UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                            userDetails, null, userDetails.getAuthorities());
                    authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                    SecurityContextHolder.getContext().setAuthentication(authentication);
                }
            }
        } catch (Exception e) {
            logger.error("Error processing authentication token: ", e);
        }

        filterChain.doFilter(request, response);
    }

    private boolean isPublicPath(String requestPath) {
        return publicPaths.stream().anyMatch(path -> {
            if (path.endsWith("/**")) {
                String prefix = path.substring(0, path.length() - 2);
                return requestPath.startsWith(prefix);
            }
            return requestPath.equals(path);
        });
    }
}
