package com.jamesdev.security.jwtv2.config.jwt;

import com.auth0.jwt.exceptions.TokenExpiredException;
import com.jamesdev.security.jwtv2.config.auth.PrincipalDetailsService;
import com.jamesdev.security.jwtv2.model.UserOauth;
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
import org.springframework.util.ObjectUtils;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Slf4j
public class JwtAuthorizationFilter extends BasicAuthenticationFilter {


    public JwtAuthorizationFilter(AuthenticationManager authenticationManager, UserService userService,JwtService jwtService, UserOauthService userOauthService,PrincipalDetailsService principalDetailsService) {
        super(authenticationManager);
        this.jwtService = jwtService;
        this.userService=userService;
        this.userOauthService = userOauthService;
        this.principalDetailsService=principalDetailsService;
    }

    private final JwtService jwtService;
    private final UserOauthService userOauthService;
    private final PrincipalDetailsService principalDetailsService;
    private final UserService userService;


    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        System.out.println("=====================================");
        System.out.println("JwtAuthorizationFilter 시작");
        /*    (1)   */
        String accessToken = jwtService.resolveCookie(request);
        String refreshToken = null;
        String username=null;
        System.out.println("accessToken : "+accessToken);
        /*    (2)   */
        //access 토큰 검증
        try{
            if(StringUtils.isNotBlank(accessToken) && jwtService.validateToken(accessToken)){
                //스프링 시큐리티로 권한 처리를 위해 세션을 넣어줌
                Authentication auth = this.getAuthentication(accessToken);
                System.out.println("세션 추가");
                SecurityContextHolder.getContext().setAuthentication(auth);
            }//access 토큰만료시 refresh 토큰 가져오기
            //TODO : 리프레시 토큰 가져와서 검증하기 & ACCESS 토큰 새로 발급해주기
        /*    (3)   */
        }catch(TokenExpiredException e){
            System.out.println("access 토큰 만료됨");
            username = jwtService.getClaimFromExpiredToken(accessToken,"username"); //만료된  토큰에서 유저네임 클레임 추출
            System.out.println("username : "+username);
            UserOauth userOauth = userOauthService.findUserOauthByUsername(username);
            if(!ObjectUtils.isEmpty(userOauth)){
                refreshToken =userOauth.getRefreshToken(); //db에서 유저네임으로 리프레시 토큰 가져오기
                System.out.println("refreshToken : "+refreshToken);
            }
        }catch(Exception e){
            SecurityContextHolder.clearContext();
            System.out.println("JwtAuthorizationFilter internal error "+ e.getMessage());
            return;
        }
        /*    (4)   */
        //refresh 토큰으로 access 토큰 발급
        if(StringUtils.isNotBlank(refreshToken)){
            try{
                try{
                    if(jwtService.validateToken(refreshToken)){
                        Authentication auth = this.getAuthentication(refreshToken);
                        SecurityContextHolder.getContext().setAuthentication(auth);

                        //새로운 accessToken 발급
                        String newAccessToken = jwtService.createToken(username).getAccessToken();
                        //쿠키에 넣어줌
                        jwtService.createCookie(response, newAccessToken);
                    }
                }catch(TokenExpiredException e){
                    System.out.println("JWT token expired : "+e.getMessage());
                }
            }catch(Exception e){
                SecurityContextHolder.clearContext();
                System.out.println("JwtAuthorizationFilter internal error "+ e.getMessage());
                return;
            }
        }

        filterChain.doFilter(request,response);
    }

    /*    (5)   */
    public Authentication getAuthentication(String token){
        String username=jwtService.getClaim(token,"username");
        UserDetails userDetails = principalDetailsService.loadUserByUsername(username);
        return new UsernamePasswordAuthenticationToken(userDetails, null,userDetails.getAuthorities());
    }

}
