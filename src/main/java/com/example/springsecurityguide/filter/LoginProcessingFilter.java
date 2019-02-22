package com.example.springsecurityguide.filter;


import com.example.springsecurityguide.domain.SecurityMember;
import com.example.springsecurityguide.dto.LoginMemberDto;
import com.example.springsecurityguide.dto.TokenDto;
import com.example.springsecurityguide.token.JwtFactory;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Collections;


public class LoginProcessingFilter extends AbstractAuthenticationProcessingFilter {


    private final JwtFactory jwtFactory;

    private final ObjectMapper objectMapper;


    public LoginProcessingFilter(String defaultFilterProcessesUrl, AuthenticationManager manager,JwtFactory jwtFactory,ObjectMapper objectMapper) {
        super(defaultFilterProcessesUrl);
        setAuthenticationManager(manager);
        this.jwtFactory = jwtFactory;
        this.objectMapper = objectMapper;

    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException, IOException, ServletException {

        LoginMemberDto loginMemberDto = new ObjectMapper().readValue(request.getReader(), LoginMemberDto.class);
        UsernamePasswordAuthenticationToken token =
                new UsernamePasswordAuthenticationToken(loginMemberDto.getEmail(),loginMemberDto.getPassword(), Collections.emptyList());

        return this.getAuthenticationManager().authenticate(token);
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {

        UsernamePasswordAuthenticationToken postToken = (UsernamePasswordAuthenticationToken) authResult;

        SecurityMember securityMember = (SecurityMember) postToken.getPrincipal();

        String token = jwtFactory.generateToken(securityMember.getUsername());

        TokenDto tokenDto = new TokenDto(token);

        //http header 설정
        response.setContentType(MediaType.APPLICATION_JSON_UTF8_VALUE);
        response.setStatus(HttpStatus.OK.value());
        response.getWriter().write(objectMapper.writeValueAsString(tokenDto));
        

    }

    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) throws IOException, ServletException {
        super.unsuccessfulAuthentication(request, response, failed);
        logger.info("실패");
    }
}
