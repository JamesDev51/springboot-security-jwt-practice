package com.jamesdev.security.jwtv2.config.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseCookie;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.stereotype.Service;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@Data
@Slf4j
@RequiredArgsConstructor
@Service
public class JwtService {
    @Value("${jwt.secret}")
    private String SECRET;

    @Value("${jwt.issuer}")
    private String ISSUER;

    @Value("${jwt.token-prefix}")
    private String TOKEN_PREFIX;

    @Value("${jwt.header-name}")
    private String HEADER_NAME;

    @Value("${jwt.access-token-expire-length}")
    private long ACCESS_VALIDITY_IN_MILLISECONDS;

    @Value("${jwt.refresh-token-expire-length}")
    private long REFRESH_VALIDITY_IN_MILLISECONDS;



    //토큰 생성
    public JwtModel createToken(String username){
        Map<String,Object> claims=new HashMap<>();
        claims.put("username",username);

        Date now = new Date();
        SimpleDateFormat sdf= new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");

        Date accessDate = new Date(now.getTime()+ACCESS_VALIDITY_IN_MILLISECONDS);
        Date refreshDate=new Date(now.getTime()+REFRESH_VALIDITY_IN_MILLISECONDS);

        return JwtModel.builder()
                .accessToken(this.generateToken(claims,now,accessDate))
                .refreshToken(this.generateToken(claims,now,refreshDate))
                .accessTokenExpirationDate(sdf.format(accessDate))
                .refreshTokenExpirationDate(sdf.format(refreshDate))
                .build();
    }

    //토큰 발급
    public String generateToken(Map<String, Object> claims, Date now, Date expirationDate){
        return JWT.create()
                .withSubject("james-jwt-token")
                .withClaim("username", claims.get("username").toString())
                .withIssuer(ISSUER)
                .withIssuedAt(now)
                .withExpiresAt(expirationDate)
                .sign(Algorithm.HMAC512(SECRET));
    }

    //쿠키에 jwt 토큰을 태워보냄
    public void createCookie(HttpServletResponse response, String token) {
        ResponseCookie cookie =
                ResponseCookie.from(HEADER_NAME, token)
                        .httpOnly(true)
                        .sameSite("lax")
                        .maxAge(ACCESS_VALIDITY_IN_MILLISECONDS)
                        .path("/")
                        .build();
        response.addHeader("Set-Cookie",cookie.toString());
    }

    //쿠키에 있는 토큰을 찾아봄
    public String resolveCookie(HttpServletRequest request){
        final Cookie[] cookies = request.getCookies(); //쿠키 가져와서
        if(cookies==null) return null; //비었으면 null
        for(Cookie cookie : cookies){
            if(cookie.getName().equals(HEADER_NAME)){
                return cookie.getValue();
            }
        }
        return null;
    }

    //토큰 검증
    public boolean validateToken(String token){
        try{
//            String rawToken=token.replace(TOKEN_PREFIX,"");
            Algorithm algorithm = Algorithm.HMAC512(SECRET);
            JWTVerifier jwtVerifier = JWT.require(algorithm).withIssuer(ISSUER).build();
            DecodedJWT decodedJWT = jwtVerifier.verify(token);
            return true;
        } catch(JwtException e) {
            log.error(e.getMessage());
            throw e;
        }
    }




    //쿠키 말고 헤더-로컬스토리지로 통신하는 방법
    //토큰을 헤더에 저장
    public void saveTokenToHeader(HttpServletResponse response, String token){
        response.setHeader(HEADER_NAME, token);
    }
    //헤더에서 토큰 가져오기
    public String resolveTokenFromHeader(HttpServletRequest request){
        return request.getHeader(HEADER_NAME);
    }



//    public Authentication getAuthentication(String token) {
//        UserDetails userDetails = loginService.loadUserByUsername(this.getClaims(token, "sub"));
//        return new UsernamePasswordAuthenticationToken(userDetails, "", userDetails.getAuthorities());
//    }


    public Map<String, Claim> extractAllClaims(String token ){
//        String rawToken=token.replace(TOKEN_PREFIX,"");
        return  JWT.require(Algorithm.HMAC512(SECRET))
                .build().verify(token).getClaims();
    }

    public String getClaim(String token, String key){
        return this.extractAllClaims(token).get(key).toString().replaceAll("\"", "");
    }

    public String getClaimFromExpiredToken(String token,String key){
        return JWT.decode(token).getClaim(key).toString();
    }

}

/**
 *                     JWT.require(Algorithm.HMAC512(JwtProperties.SECRET))
 *                             .build().verify(rawJwtToken)
 *                             .getClaim("username")
 *                             .asString();
 */
