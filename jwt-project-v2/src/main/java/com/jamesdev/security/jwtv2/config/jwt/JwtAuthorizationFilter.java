package com.jamesdev.security.jwtv2.config.jwt;

import com.auth0.jwt.exceptions.TokenExpiredException;
import com.jamesdev.security.jwtv2.config.auth.PrincipalDetailsService;
import com.jamesdev.security.jwtv2.service.UserOauthService;
import com.jamesdev.security.jwtv2.service.UserService;
import com.nimbusds.oauth2.sdk.util.StringUtils;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Slf4j
public class JwtAuthorizationFilter extends BasicAuthenticationFilter {

    public JwtAuthorizationFilter(AuthenticationManager authenticationManager, JwtService jwtService, UserService userService,  UserOauthService userOauthService,PrincipalDetailsService principalDetailsService) {
        super(authenticationManager);
        this.jwtService = jwtService;
        this.userService = userService;
        this.userOauthService = userOauthService;
        this.principalDetailsService=principalDetailsService;
    }

    private final JwtService jwtService;
    private final UserService userService;
    private final UserOauthService userOauthService;
    private final PrincipalDetailsService principalDetailsService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        System.out.println("=====================================");
        System.out.println("JwtAuthorizationFilter 시작");
        String accessToken = jwtService.resolveCookie(request);
        String refreshToken = null;
        System.out.println("accessToken : "+accessToken);
        //access 토큰 검증
        try{
            if(StringUtils.isNotBlank(accessToken) && jwtService.validateToken(accessToken)){
                //스프링 시큐리티로 권한 처리를 위해 세션을 넣어줌
                Authentication auth = this.getAuthentication(accessToken);
                System.out.println("세션 추가");
                SecurityContextHolder.getContext().setAuthentication(auth);
            }//access 토큰만료시 refresh 토큰 가져오기
            //TODO : 리프레시 토큰 가져와서 검증하기 & ACCESS 토큰 새로 발급해주기
        }catch(TokenExpiredException e){
            System.out.println("access 토큰 만료됨");
            String username = jwtService.getClaimFromExpiredToken(accessToken,"username");
            System.out.println("username : "+username);
        }

        filterChain.doFilter(request,response);
    }


    public Authentication getAuthentication(String token){
        String username=jwtService.getClaim(token,"username");
        UserDetails userDetails = principalDetailsService.loadUserByUsername(username);
        return new UsernamePasswordAuthenticationToken(userDetails, null,userDetails.getAuthorities());
    }

}
