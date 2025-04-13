package com.zorth.model;

import lombok.Data;

@Data
public class ZorthUser {

    private Long id;
    private String username;
    private String password;
    private String roles;

}
