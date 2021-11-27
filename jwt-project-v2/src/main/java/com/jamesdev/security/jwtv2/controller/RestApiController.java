package com.jamesdev.security.jwtv2.controller;

import com.jamesdev.security.jwtv2.dto.ResponseDto;
import com.jamesdev.security.jwtv2.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@RequiredArgsConstructor
@RestController
public class RestApiController {
    private final UserService userService;

    @PostMapping("/user")
    public ResponseDto<String> user(){
        return new ResponseDto<>(HttpStatus.OK.value(), "회원 전용 주소");
    }
    @PostMapping("/manager")
    public ResponseDto<String> manager(){
        return new ResponseDto<>(HttpStatus.OK.value(), "매니저 전용 주소");
    }
    @PostMapping("/admin")
    public ResponseDto<String> admin(){
        return new ResponseDto<>(HttpStatus.OK.value(), "어드민 전용 주소");
    }
}
