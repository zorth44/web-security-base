package com.zorth.service;

import com.zorth.api.request.LoginRequest;
import com.zorth.model.GitHubUserInfo;
import com.zorth.model.ZorthUser;
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

    /**
     * Handles GitHub OAuth2 login process.
     * 
     * @param code The authorization code received from GitHub
     * @return A JWT token if authentication is successful
     * @throws AuthenticationException if authentication fails
     */
    String handleGitHubLogin(String code) throws AuthenticationException;

    /**
     * Retrieves user information from GitHub using the access token.
     * 
     * @param accessToken The GitHub access token
     * @return GitHub user information
     */
    GitHubUserInfo getGitHubUserInfo(String accessToken);

    /**
     * Creates or updates a local user based on GitHub user information.
     * 
     * @param githubUserInfo The GitHub user information
     * @return The created or updated local user
     */
    ZorthUser createOrUpdateGitHubUser(GitHubUserInfo githubUserInfo);


} 