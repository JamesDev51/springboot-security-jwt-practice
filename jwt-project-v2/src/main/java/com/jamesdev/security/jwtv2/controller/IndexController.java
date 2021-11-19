package com.jamesdev.security.jwtv2.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@RequiredArgsConstructor
@Controller
public class IndexController {

    @GetMapping("/joinForm")
    public String joinForm(){
        return "joinForm";
    }

@GetMapping("/loginForm")
public String loginForm(){
    return "loginForm";
}


}
