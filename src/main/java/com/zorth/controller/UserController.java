package com.zorth.controller;

import com.zorth.api.request.LoginRequest;
import com.zorth.api.request.LogoutRequest;
import com.zorth.service.AuthService;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.bind.annotation.*;

@RestController
public class UserController {

    private final RedisTemplate<String, String> redisTemplate;
    private final AuthService authService;

    public UserController(RedisTemplate<String, String> redisTemplate,
                          AuthService authService) {
        this.redisTemplate = redisTemplate;
        this.authService = authService;
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest loginRequest) {
        try {
            String token = authService.login(loginRequest);
            return ResponseEntity.ok(token);

        } catch (AuthenticationException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Authentication failed: " + e.getMessage());
        }
    }

    @PostMapping("/logout")
    public String logout(@RequestBody LogoutRequest logoutRequest) {
        redisTemplate.delete(logoutRequest.getUsername());
        return "Logged out successfully";
    }

    @GetMapping("/admin")
    @PreAuthorize("hasRole('ADMIN')")
    public String auth(){
        return "success";
    }

}
