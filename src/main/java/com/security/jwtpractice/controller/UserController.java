package com.security.jwtpractice.controller;

import com.security.jwtpractice.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@RequiredArgsConstructor
@Controller
public class UserController {

    private final UserRepository userRepository;
    private final  BCryptPasswordEncoder bCryptPasswordEncoder;


    @GetMapping("/joinForm")
    public String joinForm(){
        return "joinForm";
    }
    @GetMapping("/loginForm")
    public String loginForm(){
        return "loginForm";
    }



    @GetMapping("/user")
    public String user(){
        return "user";
    }
    @GetMapping("/admin")
    public String admin(){
        return "admin";
    }

}
