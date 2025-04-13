package com.zorth.api.request;

import lombok.Data;

@Data
public class LogoutRequest {

    private String username;
    private String password;

}
