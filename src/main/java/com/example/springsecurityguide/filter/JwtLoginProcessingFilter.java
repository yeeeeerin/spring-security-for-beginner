package com.example.springsecurityguide.filter;

import com.example.springsecurityguide.dto.TokenDto;
import com.example.springsecurityguide.handler.JwtLoginAuthenticationFailureHandler;
import com.example.springsecurityguide.handler.JwtLoginAuthenticationSuccessHandler;
import com.example.springsecurityguide.utils.JwtTokenExtractor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.RequestMatcher;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Collections;

public class JwtLoginProcessingFilter extends AbstractAuthenticationProcessingFilter {

    @Autowired
    JwtTokenExtractor tokenExtractor;

    @Autowired
    JwtLoginAuthenticationFailureHandler failureHandler;

    @Autowired
    JwtLoginAuthenticationSuccessHandler successHandler;

    public JwtLoginProcessingFilter(RequestMatcher requiresAuthenticationRequestMatcher) {
        super(requiresAuthenticationRequestMatcher);
    }


    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException, IOException, ServletException {
        String tokenPayload = request.getHeader("Authorization");

        UsernamePasswordAuthenticationToken token =
                new UsernamePasswordAuthenticationToken(this.tokenExtractor.extract(tokenPayload),null);

        return super.getAuthenticationManager().authenticate(token);
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        this.successHandler.onAuthenticationSuccess(request, response, authResult);
        chain.doFilter(request, response);
    }

    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) throws IOException, ServletException {
        this.failureHandler.onAuthenticationFailure(request, response, failed);
    }
}
