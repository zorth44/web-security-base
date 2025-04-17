package com.zorth.model;

import lombok.Data;
import java.time.LocalDateTime;

@Data
public class ZorthUser {
    private Long id;
    private String username;
    private String password;
    private String roles;
    private String authType;
    private String githubId;
    private String email;
    private String avatarUrl;
    private String githubUsername;
    private LocalDateTime lastLoginTime;
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;
}