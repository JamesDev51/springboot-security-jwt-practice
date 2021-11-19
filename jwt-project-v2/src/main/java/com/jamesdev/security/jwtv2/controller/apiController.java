package com.jamesdev.security.jwtv2.controller;

import com.jamesdev.security.jwtv2.dto.ResponseDto;
import com.jamesdev.security.jwtv2.dto.UserDto;
import com.jamesdev.security.jwtv2.service.UserService;
import lombok.RequiredArgsConstructor;
import net.minidev.json.JSONObject;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@RequiredArgsConstructor
@RestController
public class apiController {
    private final UserService userService;

    @PostMapping("/api/joinProc")
    public ResponseDto<String> joinProc(UserDto userDto){
        userService.registerUser(userDto);
        return new ResponseDto<>(HttpStatus.OK.value(), "회원가입 완료");
    }
    @PostMapping("/api/loginProc")
    public ResponseDto<JSONObject> loginProc(UserDto userDto){
        return null;
    }
}
