package com.zorth.model;

import lombok.Data;

@Data
public class GitHubUserInfo {
    
    private String id;
    private String login;
    private String email;
    private String avatar_url;
    private String name;

}
