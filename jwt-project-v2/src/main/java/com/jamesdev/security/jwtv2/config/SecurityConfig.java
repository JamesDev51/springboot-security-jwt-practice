package com.jamesdev.security.jwtv2.config;

import com.jamesdev.security.jwtv2.config.jwt.JwtAuthenticationFilter;
import com.jamesdev.security.jwtv2.config.jwt.JwtAuthorizationFilter;
import com.jamesdev.security.jwtv2.config.jwt.JwtService;
import com.jamesdev.security.jwtv2.service.UserOauthService;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.filter.CorsFilter;

@RequiredArgsConstructor
@EnableWebSecurity
@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final CorsFilter corsFilter;
    private  final UserOauthService userOauthService;
    private  final JwtService jwtService;



    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder(){
        return new BCryptPasswordEncoder();
    }


    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .csrf().disable()
                .formLogin().disable()
                .httpBasic().disable()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);

        http
                .headers()
                .cacheControl().disable()
                .frameOptions().sameOrigin()
                .httpStrictTransportSecurity().disable();

        http
                .authorizeRequests()
                .antMatchers("/user/**")
                .authenticated()
                .antMatchers("/manager/**")
                .access("hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
                .antMatchers("/admin/**")
                .access("hasRole('ROLE_ADMIN')")
                .anyRequest()
                .permitAll();

        http
                .addFilter(corsFilter)
                .addFilter(new JwtAuthenticationFilter(authenticationManager(),userOauthService,jwtService))
                .addFilterBefore(new JwtAuthorizationFilter(jwtService,userDetailsService()), UsernamePasswordAuthenticationFilter.class);


    }

    @Override
    protected AuthenticationManager authenticationManager() throws Exception {
        return super.authenticationManager();
    }

    @Override
    protected UserDetailsService userDetailsService() {
        return super.userDetailsService();
    }
}
