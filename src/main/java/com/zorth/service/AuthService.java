package com.zorth.service;

import com.zorth.api.request.LoginRequest;
import org.springframework.security.core.AuthenticationException;
// import com.zorth.model.GitHubUserInfo;
// import com.zorth.model.ZorthUser;

public interface AuthService {

    /**
     * Authenticates a user based on the provided login request.
     *
     * @param loginRequest The login request containing username and password.
     * @return A JWT token if authentication is successful.
     * @throws AuthenticationException if authentication fails.
     */
    String login(LoginRequest loginRequest) throws AuthenticationException;

    // String handleGitHubLogin(String code) throws AuthenticationException;
    // GitHubUserInfo getGitHubUserInfo(String accessToken);
    // ZorthUser createOrUpdateGitHubUser(GitHubUserInfo githubUserInfo);
} 