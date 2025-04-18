package com.zorth.service.impl;

import com.zorth.api.request.LoginRequest;
import com.zorth.client.GitHubClient;
import com.zorth.mapper.ZorthUserMapper;
import com.zorth.model.GitHubUserInfo;
import com.zorth.model.ZorthUser;
import com.zorth.service.AuthService;
import com.zorth.service.CustomUserDetailsService;
import com.zorth.util.JwtTokenUtil;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.LocalDateTime;

@Service
public class AuthServiceImpl implements AuthService {

    private static final Logger logger = LoggerFactory.getLogger(AuthServiceImpl.class);
    private final RedisTemplate<String, String> redisTemplate;
    private final CustomUserDetailsService customUserDetailsService;
    private final PasswordEncoder passwordEncoder;
    private final GitHubClient gitHubClient;
    private final ZorthUserMapper zorthUserMapper;

    public AuthServiceImpl(RedisTemplate<String, String> redisTemplate,
                         CustomUserDetailsService customUserDetailsService,
                         PasswordEncoder passwordEncoder,
                         GitHubClient gitHubClient,
                         ZorthUserMapper zorthUserMapper) {
        this.redisTemplate = redisTemplate;
        this.customUserDetailsService = customUserDetailsService;
        this.passwordEncoder = passwordEncoder;
        this.gitHubClient = gitHubClient;
        this.zorthUserMapper = zorthUserMapper;
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
            String token = JwtTokenUtil.generateToken(loginRequest.getUsername(), "JWT");
            
            // Store token in Redis
            redisTemplate.opsForValue().set(loginRequest.getUsername(), token);
            
            logger.info("User {} successfully authenticated", loginRequest.getUsername());
            return token;
            
        } catch (Exception e) {
            logger.error("Authentication error for user {}: {}", loginRequest.getUsername(), e.getMessage());
            throw new BadCredentialsException("Invalid username or password");
        }
    }

    @Override
    public String handleGitHubLogin(String code) throws AuthenticationException {
        try {
            // 1. Get access token from GitHub
            String accessToken = gitHubClient.getAccessToken(code);
            
            // 2. Get user info from GitHub
            GitHubUserInfo githubUserInfo = gitHubClient.getUserInfo(accessToken);
            
            // 3. Create or update local user
            ZorthUser user = createOrUpdateGitHubUser(githubUserInfo);
            
            // 4. Generate JWT token
            String token = JwtTokenUtil.generateToken(user.getUsername(), "OAUTH");
            
            // 5. Store token in Redis
            redisTemplate.opsForValue().set(user.getUsername(), token);
            
            logger.info("GitHub user {} successfully authenticated", user.getUsername());
            return token;
            
        } catch (Exception e) {
            logger.error("GitHub authentication error: {}", e.getMessage());
            throw new BadCredentialsException("GitHub authentication failed");
        }
    }

    @Override
    public GitHubUserInfo getGitHubUserInfo(String accessToken) {
        return gitHubClient.getUserInfo(accessToken);
    }

    @Override
    public ZorthUser createOrUpdateGitHubUser(GitHubUserInfo githubUserInfo) {
        // 1. Check if user exists by GitHub ID
        logger.info("Looking up user with GitHub ID: {}", githubUserInfo.getId());
        ZorthUser existingUser = zorthUserMapper.findByGithubId(githubUserInfo.getId());
        logger.info("Found existing user: {}", existingUser);
        
        if (existingUser != null) {
            // Update existing user
            existingUser.setGithubUsername(githubUserInfo.getLogin());
            existingUser.setEmail(githubUserInfo.getEmail());
            existingUser.setAvatarUrl(githubUserInfo.getAvatar_url());
            existingUser.setLastLoginTime(LocalDateTime.now());
            existingUser.setUpdatedAt(LocalDateTime.now());
            zorthUserMapper.updateUser(existingUser);
            return existingUser;
        } else {
            // Create new user
            logger.info("Creating new user for GitHub ID: {}", githubUserInfo.getId());
            ZorthUser newUser = new ZorthUser();
            newUser.setUsername(githubUserInfo.getLogin());
            newUser.setGithubId(githubUserInfo.getId());
            newUser.setGithubUsername(githubUserInfo.getLogin());
            newUser.setEmail(githubUserInfo.getEmail());
            newUser.setAvatarUrl(githubUserInfo.getAvatar_url());
            newUser.setAuthType("GITHUB");
            newUser.setRoles("USER"); // Default role
            newUser.setPassword(passwordEncoder.encode("github_" + githubUserInfo.getId() + "_" + System.currentTimeMillis()));
            newUser.setLastLoginTime(LocalDateTime.now());
            newUser.setCreatedAt(LocalDateTime.now());
            newUser.setUpdatedAt(LocalDateTime.now());
            zorthUserMapper.insertUser(newUser);
            return newUser;
        }
    }

    @Override
    public String validateGitHubToken(String token) {
        try {
            // GitHubUserInfo userInfo = gitHubClient.getUserInfo(token);
            // if (userInfo != null) {
            //     return userInfo.getLogin();
            // }
            if (!JwtTokenUtil.isTokenExpired(token)) {
                return JwtTokenUtil.getUsernameFromToken(token);
            }
        } catch (Exception e) {
            logger.error("Failed to validate GitHub token: ", e);
        }
        return null;
    }
} 