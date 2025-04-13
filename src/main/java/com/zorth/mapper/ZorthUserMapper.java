package com.zorth.mapper;

import com.zorth.model.ZorthUser;

public interface ZorthUserMapper {

    /**
     * 根据用户 username 查询用户信息
     *
     * @param username 用户名
     * @return 用户信息
     */
    ZorthUser findByUsername(String username);

}
