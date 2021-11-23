package com.jamesdev.security.jwtv2.config.jwt;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.jamesdev.security.jwtv2.config.auth.PrincipalDetails;
import com.jamesdev.security.jwtv2.dto.UserDto;
import com.jamesdev.security.jwtv2.service.UserOauthService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Slf4j
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    private final AuthenticationManager aUthenticationManager;
    private final JwtService jwtService;
    private final UserOauthService userOauthService;
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        System.out.println("================================");
        System.out.println("JwtAuthenticationFilter  - attemptAuthentication : 로그인 시도중");
        ObjectMapper om = new ObjectMapper();
        try{
            System.out.println("id, pw json 파싱");
            UserDto userDto = om.readValue(request.getInputStream(),UserDto.class);
            System.out.println("User Dto : "+ userDto);

            UsernamePasswordAuthenticationToken authenticationToken =
                    new UsernamePasswordAuthenticationToken(userDto.getUsername(),userDto.getPassword());
            Authentication authentication = aUthenticationManager.authenticate(authenticationToken);

            PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();

            System.out.println("로그인 성공");
            System.out.println("===========================");
            return authentication;
        }catch(UsernameNotFoundException e){
            System.out.println("유저 못 찾음 : "+e.getMessage());
        } catch(IOException e){
            System.out.println("에러발생 : " + e.getMessage());
        }
        System.out.println("로그인 실패");
        System.out.println("===============================");
        return null;
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        System.out.println("==============================");
        System.out.println("JwtAuthenticationFilter  - successfulAuthentication : 로그인 후 처리중 (JWT 토큰 만들기)");
        PrincipalDetails principalDetails = (PrincipalDetails) authResult.getPrincipal();
        String username = principalDetails.getUsername();

        JwtModel jwtModel = jwtService.createToken(username);
        jwtService.createCookie(response,jwtModel.getAccessToken()); //엑세스 토큰 쿠키에 추가
        userOauthService.deleteUserOauth(username);
        userOauthService.insertUserOauth(username,jwtModel);
    }
}
