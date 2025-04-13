package com.zorth.service;

import com.zorth.mapper.ZorthUserMapper;
import com.zorth.model.ZorthUser;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class CustomUserDetailsService implements UserDetailsService {

    private final ZorthUserMapper zorthUserMapper;

    public CustomUserDetailsService(ZorthUserMapper zorthUserMapper) {
        this.zorthUserMapper = zorthUserMapper;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        ZorthUser user = zorthUserMapper.findByUsername(username);
        if (user == null) {
            throw new UsernameNotFoundException("User not found");
        }

        return org.springframework.security.core.userdetails.User.builder()
                .username(user.getUsername())
                .password(user.getPassword())
                .roles(user.getRoles().split(","))
                .build();
    }
}
