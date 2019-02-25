package com.example.springsecurityguide.utils;

import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import javax.servlet.http.HttpServletRequest;
import java.util.List;
import java.util.stream.Collectors;

public class FilterSkipPathMatcher implements RequestMatcher {

    private OrRequestMatcher orRequestMatcher;
    private RequestMatcher requestMatcher;

    public FilterSkipPathMatcher(List<String> pathsToSkip, String processingPath) {

        //건너띌 주소 묶음
        this.orRequestMatcher = new OrRequestMatcher(
                pathsToSkip.stream()
                        .map(AntPathRequestMatcher::new)
                        .collect(Collectors.toList())
        );

        //인증을 진행할 주소
        this.requestMatcher = new AntPathRequestMatcher(processingPath);
    }

    @Override
    public boolean matches(HttpServletRequest request) {
        return !orRequestMatcher.matches(request) && requestMatcher.matches(request);
    }
}
