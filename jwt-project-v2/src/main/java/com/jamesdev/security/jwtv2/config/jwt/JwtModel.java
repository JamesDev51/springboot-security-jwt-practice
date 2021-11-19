package com.jamesdev.security.jwtv2.config.jwt;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.io.Serializable;

@Getter
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class JwtModel implements Serializable {
    private String accessToken;
    private String accessTokenExpirationDate;
    private String refreshToken;
    private String refreshTokenExpirationDate;
}
