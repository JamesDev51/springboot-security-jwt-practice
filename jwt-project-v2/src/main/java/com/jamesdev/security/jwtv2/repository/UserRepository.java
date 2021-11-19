package com.jamesdev.security.jwtv2.repository;

import com.jamesdev.security.jwtv2.model.User;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<User,Long> {
    User findByUsername(String username);
}
