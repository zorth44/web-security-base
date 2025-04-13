package com.zorth.service.impl;

import com.zorth.api.request.LoginRequest;
import com.zorth.service.AuthService;
import com.zorth.service.CustomUserDetailsService;
import com.zorth.util.JwtTokenUtil;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Service
public class AuthServiceImpl implements AuthService {

    private static final Logger logger = LoggerFactory.getLogger(AuthServiceImpl.class);
    private final RedisTemplate<String, String> redisTemplate;
    private final CustomUserDetailsService customUserDetailsService;
    private final PasswordEncoder passwordEncoder;

    public AuthServiceImpl(RedisTemplate<String, String> redisTemplate,
                         CustomUserDetailsService customUserDetailsService,
                         PasswordEncoder passwordEncoder) {
        this.redisTemplate = redisTemplate;
        this.customUserDetailsService = customUserDetailsService;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public String login(LoginRequest loginRequest) {
        try {
            // Load user details directly
            UserDetails userDetails = customUserDetailsService.loadUserByUsername(loginRequest.getUsername());
            
            // Verify password manually
            if (!passwordEncoder.matches(loginRequest.getPassword(), userDetails.getPassword())) {
                logger.warn("Authentication failed for user: {}", loginRequest.getUsername());
                throw new BadCredentialsException("Invalid username or password");
            }

            // Generate token
            String token = JwtTokenUtil.generateToken(loginRequest.getUsername());
            
            // Store token in Redis
            redisTemplate.opsForValue().set(loginRequest.getUsername(), token);
            
            logger.info("User {} successfully authenticated", loginRequest.getUsername());
            return token;
            
        } catch (Exception e) {
            logger.error("Authentication error for user {}: {}", loginRequest.getUsername(), e.getMessage());
            throw new BadCredentialsException("Invalid username or password");
        }
    }
} 