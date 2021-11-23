package com.jamesdev.security.jwtv2.model;

import lombok.*;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;

@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
@Builder
@Entity
public class UserOauth {
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Id
    private long id;
    private String refreshToken;
    private String username;
}
