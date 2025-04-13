package com.zorth.filter;

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

    public JwtAuthenticationFilter(RedisTemplate<String, String> redisTemplate,
                                 CustomUserDetailsService customUserDetailsService,
                                 List<String> publicPaths) {
        this.redisTemplate = redisTemplate;
        this.customUserDetailsService = customUserDetailsService;
        this.publicPaths = publicPaths;
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
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        String token = authHeader.substring(7);
        String username = null;

        try {
            // Validate token and get username
            if (!JwtTokenUtil.isTokenExpired(token)) {
                username = JwtTokenUtil.getUsernameFromToken(token);
                
                // Check if token exists in Redis
                String storedToken = redisTemplate.opsForValue().get(username);
                if (storedToken == null || !storedToken.equals(token)) {
                    logger.debug("Token not found in Redis or doesn't match");
                    filterChain.doFilter(request, response);
                    return;
                }
            } else {
                logger.debug("Token has expired");
                filterChain.doFilter(request, response);
                return;
            }
        } catch (Exception e) {
            logger.error("Error processing JWT token: ", e);
            filterChain.doFilter(request, response);
            return;
        }

        // If we have a valid username, load user details and set authentication
        if (username != null) {
            try {
                UserDetails userDetails = customUserDetailsService.loadUserByUsername(username);
                UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                        userDetails, null, userDetails.getAuthorities());
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authentication);
                logger.debug("Authentication successful for user: {}", username);
            } catch (Exception e) {
                logger.error("Error loading user details: ", e);
            }
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
