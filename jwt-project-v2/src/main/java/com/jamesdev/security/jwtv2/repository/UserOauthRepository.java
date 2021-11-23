package com.jamesdev.security.jwtv2.repository;

import com.jamesdev.security.jwtv2.model.UserOauth;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserOauthRepository extends JpaRepository<UserOauth,Long> {
    void deleteByUsername(String username);
}
