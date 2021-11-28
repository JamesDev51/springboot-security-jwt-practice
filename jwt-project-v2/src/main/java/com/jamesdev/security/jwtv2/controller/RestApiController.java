package com.jamesdev.security.jwtv2.controller;

import com.jamesdev.security.jwtv2.dto.ResponseDto;
import com.jamesdev.security.jwtv2.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RequiredArgsConstructor
@RestController
public class RestApiController {
    private final UserService userService;

    @GetMapping("/user")
    public ResponseDto<String> user(){
        return new ResponseDto<>(HttpStatus.OK.value(), "회원 전용 주소");
    }
    @GetMapping("/manager")
    public ResponseDto<String> manager(){
        return new ResponseDto<>(HttpStatus.OK.value(), "매니저 전용 주소");
    }
    @GetMapping("/admin")
    public ResponseDto<String> admin(){
        return new ResponseDto<>(HttpStatus.OK.value(), "어드민 전용 주소");
    }
}
