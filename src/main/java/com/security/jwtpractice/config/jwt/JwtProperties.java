package com.security.jwtpractice.config.jwt;

public interface JwtProperties {
    String SECRET = "cos";
    int EXPIRATION_TIME = 10000 * 30 ;
    String TOKEN_PREFIX = "Bearer ";
    String HEADER_STRING = "Authorization";

}
