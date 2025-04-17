package com.zorth.mapper;

import com.zorth.model.ZorthUser;
import org.apache.ibatis.annotations.Mapper;

@Mapper
public interface ZorthUserMapper {

    /**
     * 根据用户 username 查询用户信息
     *
     * @param username 用户名
     * @return 用户信息
     */
    ZorthUser findByUsername(String username);

    /**
     * 根据GitHub ID查询用户信息
     *
     * @param githubId GitHub用户ID
     * @return 用户信息
     */
    ZorthUser findByGithubId(String githubId);

    /**
     * 更新用户信息
     *
     * @param user 用户信息
     */
    void updateUser(ZorthUser user);

    /**
     * 插入新用户
     *
     * @param user 用户信息
     */
    void insertUser(ZorthUser user);
}
