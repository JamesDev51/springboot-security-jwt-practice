package com.security.jwtpractice.config.jwt;

/*
기존 form
 */

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.security.jwtpractice.config.auth.PrincipalDetails;
import com.security.jwtpractice.model.User;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Date;

@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    private final AuthenticationManager authenticationManager;

    //login 요청을 하면 로그인 시도를 위해서 실행되는 함수
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        System.out.println("================================");
        System.out.println("JwtAuthenticationFilter  - attemptAuthentication : 로그인 시도중");
        /*
        로그인 순서
        1. username, password 받음
        2. 정상인지 로그인 시도를 해봄, authenticationManager 로 로그인 시도를 하면 PrincipalDetailsService 호출
        loadUserByUsername() 함수가 자동으로 실행 됨.
        3. PrincipalDetails 를 세션에 담는 이유 -> 권한 관리를 위해
        4. JWT 토큰을 만들어서 응답해주면 됨
         */
        ObjectMapper om = new ObjectMapper(); //JSON 파싱
        try{
            System.out.println("id,pw json 파싱");
            User user = om.readValue(request.getInputStream(), User.class); //req 에 id,pw 정보가 json 형식으로 전달 -> 파싱
            System.out.println("User Entity : "+user);

            /*유저 인증 토큰을 만들어서 authenticationManager 에 넘겨주면 PrincipalDetailsService 의 loadUserByUsername()
            함수가 실행됨 -> db에 있는 username, password 가 일치하면  Authentication 만들어짐
            */
            UsernamePasswordAuthenticationToken authenticationToken =
                    new UsernamePasswordAuthenticationToken(user.getUsername(),user.getPassword()); //유저 검증을 위해 id,pw를 사용해서 토큰 만듬
            Authentication authentication = authenticationManager.authenticate(authenticationToken);

            PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
            System.out.println("db 에서 찾은 유저 네임 : "+principalDetails.getUser().getUsername());
            /*
            authentication 객체를 return 해주면  session 영역에 저장됨
            리턴의 이유는 권한 관리를 security가 대신 해주기 때문에 편하려고 하는거임
            굳이 JWT 토큰을 사용하면서 세션을 만들 이유가 없지만, 권한 처리를 편하게 하기 위해 SESSION에 넣어줌
            */
            System.out.println("로그인 성공");
            System.out.println("===============================");
            //TODO : JWT 토큰 만들기
            return authentication;
        }catch(IOException e){
            System.out.println("에러 발생 : "+ e);
        }
        System.out.println("로그인 실패 ");
        System.out.println("===============================");
        return null;
    }

    /*
    attemptAuthentication 실행 후 인증이 정상적으로 처리되면 successfulAuthentication 함수가 실행
    JWT 토큰을 만들어서 request 요청한 사용자에게 JWT 토큰을 response 해주면 됨
     */
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        System.out.println("=====================================");
        System.out.println("JwtAuthenticationFilter  - successfulAuthentication : 로그인 후 처리중 (JWT 토큰 만들기)");
        //이 정보를 토대로 jwt 토큰을 만듬
        PrincipalDetails principalDetails = (PrincipalDetails) authResult.getPrincipal();

        //hash 암호 방식
        String jwtToken = JWT.create()
                .withSubject("cos토큰") //subject -> 토큰 이름
                .withExpiresAt(new Date(System.currentTimeMillis()+(1000*60*10))) //토큰이 얼마나 유요한지 -> 만료시간 설정
                .withClaim("id",principalDetails.getUser().getId()) //withClaim -> 내가 넣고싶은 (key-value)
                .withClaim("username",principalDetails.getUser().getUsername())
                .sign(Algorithm.HMAC512(JwtProperties.SECRET)); // "cos"가 서버만 아는 secret 값
        System.out.println("JWT 토큰 정보 : "+jwtToken);
        //헤더에 Authorization - Bearer (jwt 토큰) 형식으로 담아줌
        response.addHeader(JwtProperties.HEADER_STRING,JwtProperties.TOKEN_PREFIX+jwtToken);
        System.out.println("successfulAuthentication 종료 : 인증 완료 후 jwt ");
    }
}

/*
기존 form login 방식
스프링 시큐리티에서 UsernamePasswordAuthenticationFilter 가 알아서 처리를 해줌
login 요청을 해서 username, password 전송하면 필터가 동작을 함
서버쪽 세션 id 생성 -> 클라이언트 쿠키 세션 id를 응답
요청할 때마다 쿠키값 세션 id를 항상 들고 서버쪽으로 요청을 하기 때문에 session.getAttribute("세션값");
서버는 세션 id가 유효한지 판단을 해서 유효하면 인증이 필요한 페이지로 접근하게 하면 된다.

===================================

jwt 토큰 방식
username, password 로그인 정상이면 jwt 토큰을 생성
클라이언트 쪽으로 헤더를 통해 jwt 토큰을 응답
요청을 할 때마다 jwt 토큰을 가지고 요청을 해야함
서버는 jwt 토큰이 유효한지를 판단함 (이 필터를 만들어야 함 )
TODO : JWT 토큰이 유효한지 검사하는 필터 만들기
 */
