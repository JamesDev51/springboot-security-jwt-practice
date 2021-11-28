package com.jamesdev.security.jwtv2.service;

import com.jamesdev.security.jwtv2.dto.UserDto;
import com.jamesdev.security.jwtv2.model.RoleType;
import com.jamesdev.security.jwtv2.model.User;
import com.jamesdev.security.jwtv2.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

@RequiredArgsConstructor
@Service
public class UserService {

@Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder(){
        return this.bCryptPasswordEncoder;
    }

    private final UserRepository userRepository;

    public final BCryptPasswordEncoder bCryptPasswordEncoder= new BCryptPasswordEncoder();
    public void registerUser(UserDto userDto){
        String username=userDto.getUsername();
        String rawPassword=userDto.getPassword();
        String encPassword=bCryptPasswordEncoder.encode(rawPassword);
        RoleType role;
        if(username.startsWith("admin_")){
            role=RoleType.ROLE_ADMIN;
        }else if(username.startsWith("manager_")){
            role= RoleType.ROLE_MANAGER;
        }else{
            role=RoleType.ROLE_USER;
        }
        User user= User.builder()
                .username(username)
                .password(encPassword)
                .role(role)
                .build();
        userRepository.save(user);
}

    public User findUserByUsername(String username){
        return userRepository.findByUsername(username);
    }

}
