package com.example.springsecurityguide.utils;


import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

@Component
public class JwtTokenExtractor {
    public static final String HEADER_PREFIX = "Bearer ";

    public String extract(final String header) {
        if (StringUtils.isEmpty(header)) {
            throw new AuthenticationServiceException("Authorization header가 없습니다.");
        }

        if (header.length() < HEADER_PREFIX.length()) {
            throw new AuthenticationServiceException("authorization header size가 옳지 않습니다.");
        }

        if (!header.startsWith(HEADER_PREFIX)) {
            throw new AuthenticationServiceException("올바른 header형식이 아닙니다.");
        }

        return header.substring(HEADER_PREFIX.length());
    }
}
