package com.example.springsecurityguide.provider;

import com.example.springsecurityguide.domain.SecurityMember;
import com.example.springsecurityguide.utils.JwtFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Component;

public class JwtAuthenticationProvider implements AuthenticationProvider {

    @Autowired
    private JwtFactory jwtFactory;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String token = (String) authentication.getPrincipal();
        SecurityMember member = jwtFactory.decodeToken(token);
        return new UsernamePasswordAuthenticationToken(member, member.getPassword(), member.getAuthorities());

    }

    @Override
    public boolean supports(Class<?> authentication) {
        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
