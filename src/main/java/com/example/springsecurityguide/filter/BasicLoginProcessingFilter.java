package com.example.springsecurityguide.filter;

import com.example.springsecurityguide.dto.LoginMemberDto;
import com.example.springsecurityguide.handler.BasicLoginAuthenticationSuccessHandler;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.RequestMatcher;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Collections;

public class BasicLoginProcessingFilter extends AbstractAuthenticationProcessingFilter {

    @Autowired
    BasicLoginAuthenticationSuccessHandler successHandler;

    /*
    * todo urlmatcher랑 string 두개의 형식으로 생성자 생성하는거 설명하기
    * */
    protected BasicLoginProcessingFilter(String defaultFilterProcessesUrl) {
        super(defaultFilterProcessesUrl);
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException, IOException, ServletException {
        LoginMemberDto loginMemberDto;
        loginMemberDto = new ObjectMapper().readValue(request.getReader(), LoginMemberDto.class);
        UsernamePasswordAuthenticationToken token =
                new UsernamePasswordAuthenticationToken(loginMemberDto.getEmail(),loginMemberDto.getPassword(), Collections.emptyList());

        return this.getAuthenticationManager().authenticate(token);
    }
}
