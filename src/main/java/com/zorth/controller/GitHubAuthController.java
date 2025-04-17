package com.zorth.controller;

import com.zorth.client.GitHubClient;
import com.zorth.service.AuthService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/auth")
public class GitHubAuthController {

    private final GitHubClient gitHubClient;
    private final AuthService authService;

    public GitHubAuthController(GitHubClient gitHubClient, AuthService authService) {
        this.gitHubClient = gitHubClient;
        this.authService = authService;
    }

    @GetMapping("/github/login")
    public ResponseEntity<String> githubLogin() {
        // 重定向到 GitHub 授权页面
        String authorizationUrl = gitHubClient.buildAuthorizationUrl();
        return ResponseEntity.ok(authorizationUrl);
    }

    @GetMapping("/github/callback")
    public ResponseEntity<String> githubCallback(@RequestParam String code) {
        try {
            // 使用 AuthService 处理 GitHub 登录
            String token = authService.handleGitHubLogin(code);
            return ResponseEntity.ok("{\"token\":\"" + token + "\"}");
        } catch (Exception e) {
            return ResponseEntity.badRequest().body("{\"error\":\"Authentication failed\"}");
        }
    }
} 