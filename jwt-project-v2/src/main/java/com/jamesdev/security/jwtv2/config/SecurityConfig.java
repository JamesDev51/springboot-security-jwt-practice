package com.jamesdev.security.jwtv2.config;

import com.jamesdev.security.jwtv2.config.auth.PrincipalDetailsService;
import com.jamesdev.security.jwtv2.config.jwt.JwtAuthenticationFilter;
import com.jamesdev.security.jwtv2.config.jwt.JwtAuthorizationFilter;
import com.jamesdev.security.jwtv2.config.jwt.JwtService;
import com.jamesdev.security.jwtv2.service.UserOauthService;
import com.jamesdev.security.jwtv2.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.web.filter.CorsFilter;
/*  (1)  */
@RequiredArgsConstructor
@EnableWebSecurity
@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final CorsFilter corsFilter;
    private  final UserOauthService userOauthService;
    private  final JwtService jwtService;
    private  final UserService userService;
    private final PrincipalDetailsService principalDetailsService;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        /*  (2)  */
        http
                .csrf().disable()
                .formLogin().disable()
                .httpBasic().disable()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);

        /*  (3)  */
        http
                .headers()
                .cacheControl().disable()
                .contentTypeOptions().disable()
                .frameOptions().sameOrigin()
                .httpStrictTransportSecurity().disable()
                .xssProtection().disable();

        /*  (4)  */
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

        /*  (5)  */
        http
                .logout()
                .logoutUrl("/logout")
                .deleteCookies(jwtService.getHEADER_NAME())
                .logoutSuccessUrl("/loginForm")
                .invalidateHttpSession(true);

        /*  (6)  */
        http
                .addFilter(corsFilter)
                .addFilter(new JwtAuthenticationFilter(authenticationManager(),userOauthService,jwtService))
                .addFilter(new JwtAuthorizationFilter(authenticationManager(),jwtService,userService,userOauthService,principalDetailsService));


    }

    /*  (7)  */
    @Override
    protected AuthenticationManager authenticationManager() throws Exception {
        return super.authenticationManager();
    }
}
