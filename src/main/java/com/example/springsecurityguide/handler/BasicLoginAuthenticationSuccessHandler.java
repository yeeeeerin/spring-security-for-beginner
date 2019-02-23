package com.example.springsecurityguide.handler;

import com.example.springsecurityguide.domain.SecurityMember;
import com.example.springsecurityguide.dto.TokenDto;
import com.example.springsecurityguide.utils.JwtFactory;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
public class BasicLoginAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

    @Autowired
    private ObjectMapper objectMapper;
    @Autowired
    private JwtFactory jwtFactory;


    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        SecurityMember securityMember = (SecurityMember) authentication.getPrincipal();

        String token = jwtFactory.generateToken(securityMember);

        TokenDto tokenDto = new TokenDto(token);

        makeResponse(response,tokenDto);

    }

    private void makeResponse(HttpServletResponse response, TokenDto tokenDto) throws IOException {

        response.setContentType(MediaType.APPLICATION_JSON_UTF8_VALUE);
        response.setStatus(HttpStatus.OK.value());
        response.getWriter().write(objectMapper.writeValueAsString(tokenDto));
        //objectMapper.writeValue(response.getWriter(), tokenDto);

    }
}
