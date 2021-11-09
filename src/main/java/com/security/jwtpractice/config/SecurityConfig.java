package com.security.jwtpractice.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.filter.CorsFilter;

@RequiredArgsConstructor
@EnableWebSecurity
@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    private final CorsFilter corsFilter;
    @Bean
    public BCryptPasswordEncoder encodePWD(){return new BCryptPasswordEncoder();}



    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable();
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS) //stateless -> 세션을 사용하지 않겠다.
                .and()
                .addFilter(corsFilter) //@CrossOrigin(인증 x ) , 시큐리티 필터에 등록(인증 o)
                .formLogin().disable() //form 로그인 사용 안함
                .httpBasic().disable() //id,pw를 사용한 기본 인증방식을 사용하지 않고 토큰을 사용한 bearer 방식 사용
                .authorizeRequests()
                .antMatchers("/api/v1/user/**")
                .access("hasRole('ROLE_USER') or  hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
                .antMatchers("/api/v1/manger/**")
                .access("hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
                .antMatchers("/api/v1/admin/**")
                .access(" hasRole('ROLE_ADMIN')")
                .anyRequest().permitAll();
    }
}
