package com.zorth.client;

import com.zorth.model.GitHubUserInfo;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.stereotype.Component;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Map;

@Component
public class GitHubClient {
    private final RestTemplate restTemplate;
    private final String clientId;
    private final String clientSecret;
    private final String redirectUri;
    private static final Logger logger = LoggerFactory.getLogger(GitHubClient.class);

    public GitHubClient(RestTemplate restTemplate,
                       @Value("${github.client.id}") String clientId,
                       @Value("${github.client.secret}") String clientSecret,
                       @Value("${github.redirect.uri}") String redirectUri) {
        this.restTemplate = restTemplate;
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        this.redirectUri = redirectUri;
    }

    /**
     * 获取GitHub访问令牌
     */
    public String getAccessToken(String code) {
        String url = "https://github.com/login/oauth/access_token";
        
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        
        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add("client_id", clientId);
        params.add("client_secret", clientSecret);
        params.add("code", code);
        params.add("redirect_uri", redirectUri);

        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(params, headers);
        
        ResponseEntity<Map> response = restTemplate.postForEntity(url, request, Map.class);
        
        if (response.getStatusCode() == HttpStatus.OK && response.getBody() != null) {
            return (String) response.getBody().get("access_token");
        }
        throw new RuntimeException("Failed to get access token from GitHub");
    }

    /**
     * 获取GitHub用户信息
     */
    public GitHubUserInfo getUserInfo(String accessToken) {
        String url = "https://api.github.com/user";
        
        HttpHeaders headers = new HttpHeaders();
        headers.set("Authorization", "Bearer " + accessToken);
        
        HttpEntity<String> entity = new HttpEntity<>(headers);
        
        ResponseEntity<GitHubUserInfo> response = restTemplate.exchange(
            url, HttpMethod.GET, entity, GitHubUserInfo.class);
            
        if (response.getStatusCode() == HttpStatus.OK) {
            return response.getBody();
        }
        throw new RuntimeException("Failed to get user info from GitHub");
    }

    /**
     * 构建GitHub授权URL
     */
    public String buildAuthorizationUrl() {
        return UriComponentsBuilder.fromHttpUrl("https://github.com/login/oauth/authorize")
                .queryParam("client_id", clientId)
                .queryParam("redirect_uri", redirectUri)
                .queryParam("scope", "user:email")
                .build()
                .toUriString();
    }

    /**
     * 验证 GitHub OAuth2 令牌
     */
    public String validateToken(String accessToken) {
        String url = "https://api.github.com/user";
        
        HttpHeaders headers = new HttpHeaders();
        headers.set("Authorization", "Bearer " + accessToken);
        
        HttpEntity<String> entity = new HttpEntity<>(headers);
        
        try {
            ResponseEntity<Map> response = restTemplate.exchange(
                url, HttpMethod.GET, entity, Map.class);
                
            if (response.getStatusCode() == HttpStatus.OK && response.getBody() != null) {
                return (String) response.getBody().get("login");  // 返回 GitHub 用户名
            }
        } catch (Exception e) {
            logger.error("Failed to validate GitHub token: ", e);
        }
        return null;
    }
} 