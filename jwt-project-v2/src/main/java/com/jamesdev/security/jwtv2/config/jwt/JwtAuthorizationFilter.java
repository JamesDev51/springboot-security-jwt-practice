package com.jamesdev.security.jwtv2.config.jwt;

import com.jamesdev.security.jwtv2.service.UserService;
import com.nimbusds.oauth2.sdk.util.StringUtils;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Slf4j
@RequiredArgsConstructor
@Component
public class JwtAuthorizationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final UserService userService;
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String accessToken = jwtService.resolveCookie(request);
        String refreshToken = null;

        //access 토큰 검증
        try{
            if(StringUtils.isNotBlank(accessToken) && jwtService.validateToken(accessToken)){
                Authentication auth = jwtService.getAuthentication(accessToken);
                SecurityContextHolder.getContext().setAuthentication(auth);
            }
            // access 토큰만료시 refresh 토큰 가져오기
        }catch(JwtException e){

//            User user = userService.findUserByUsername("")
        }


    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {

        return true;
    }


}
