package com.jamesdev.security.jwtv2.repository;

import com.jamesdev.security.jwtv2.model.UserOauth;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;

public interface UserOauthRepository extends JpaRepository<UserOauth,Long> {
    @Modifying
    @Query("delete from UserOauth  where username = ?1")
    void deleteByUsername(String username);
    UserOauth findByUsername(String username);

}
