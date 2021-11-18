package com.security.jwtpractice.config;

import com.security.jwtpractice.config.jwt.JwtAuthenticationFilter;
import com.security.jwtpractice.config.jwt.JwtAuthorizationFilter;
import com.security.jwtpractice.config.jwt.JwtProperties;
import com.security.jwtpractice.repository.UserRepository;
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
    private final UserRepository userRepository;
    @Bean
    public BCryptPasswordEncoder encodePWD(){return new BCryptPasswordEncoder();}



    @Override
    protected void configure(HttpSecurity http) throws Exception {
//        http.addFilterBefore(new MyFilter3(), SecurityContextPersistenceFilter.class); //시큐리티 필터 체인에 걸어주는 법
        http
                .csrf().disable()
                .formLogin().disable()
                .httpBasic().disable()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);

        http
                .addFilter(corsFilter);

        http
                .authorizeRequests()
                .antMatchers("/api/v1/user/**")
                .authenticated()
                .antMatchers("/api/v1/manager/**")
                .access("hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
                .antMatchers("/api/v1/admin/**")
                .access(" hasRole('ROLE_ADMIN')")
                .anyRequest().permitAll();

        http
                .logout()
                .logoutUrl("/logout")
                .deleteCookies(JwtProperties.HEADER_STRING)
                .logoutSuccessUrl("/home")
                .invalidateHttpSession(true);

        http
                .addFilter(new JwtAuthenticationFilter(authenticationManager())) //authenticationManager를 param으로 줘야함
                .addFilter(new JwtAuthorizationFilter(authenticationManager(),userRepository)); //authenticationManager를 param으로 줘야함
    }
}
