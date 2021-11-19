package com.jamesdev.security.jwtv2.model;

import com.sun.istack.NotNull;
import lombok.*;

import javax.persistence.*;


@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
@Builder
@Entity
public class User {
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Id
    private long id;
    private String username;
    private String password;

    @NotNull
    @Enumerated(EnumType.STRING)
    private RoleType  role;
}
