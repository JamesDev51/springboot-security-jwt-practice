package com.security.jwtpractice.config.auth;

import com.security.jwtpractice.model.User;
import com.security.jwtpractice.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@RequiredArgsConstructor
@Service
public class PrincipalDetailsService implements UserDetailsService {

    private final UserRepository userRepository;
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        System.out.println("===============================================");
        System.out.println("PrincipalDetailsService의 loadUserByUsername");
        User user = userRepository.findByUsername(username);
        System.out.println("User Entity : "+user.toString());
        return new PrincipalDetails(user);
    }
}
