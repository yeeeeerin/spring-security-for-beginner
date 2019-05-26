package com.example.springsecurityguide.config;

import com.example.springsecurityguide.filter.BasicLoginProcessingFilter;
import com.example.springsecurityguide.filter.JwtLoginProcessingFilter;
import com.example.springsecurityguide.provider.BasicLoginSecurityProvider;
import com.example.springsecurityguide.provider.JwtAuthenticationProvider;
import com.example.springsecurityguide.utils.FilterSkipPathMatcher;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.util.Arrays;


@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
@RequiredArgsConstructor
public class SecurityConfig extends WebSecurityConfigurerAdapter {



    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }


    @Override
    protected void configure(HttpSecurity http) throws Exception {

        http
                .headers().frameOptions().disable();
        http
                .csrf().disable();
        http
                .authorizeRequests()
                .antMatchers("/h2-console/**").permitAll();
        http
                .addFilterBefore(basicLoginProcessingFilter(), UsernamePasswordAuthenticationFilter.class)
                .addFilterBefore(jwtLoginProcessingFilter(),UsernamePasswordAuthenticationFilter.class);

    }

    @Bean
    public BasicLoginSecurityProvider basicLoginSecurityProvider(){
        return new BasicLoginSecurityProvider();

    }

    @Bean
    public JwtAuthenticationProvider jwtAuthenticationProvider(){
        return new JwtAuthenticationProvider();
    }

    @Bean
    protected BasicLoginProcessingFilter basicLoginProcessingFilter() throws Exception {
        BasicLoginProcessingFilter filter = new BasicLoginProcessingFilter("/login");
        filter.setAuthenticationManager(super.authenticationManagerBean());
        return filter;
    }

    @Bean
    protected JwtLoginProcessingFilter jwtLoginProcessingFilter() throws Exception{
        FilterSkipPathMatcher matchar = new FilterSkipPathMatcher(Arrays.asList("/login","/signUp"), "/**");
        JwtLoginProcessingFilter filter = new JwtLoginProcessingFilter(matchar);
        filter.setAuthenticationManager(super.authenticationManagerBean());
        return filter;
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) {
        auth
                .authenticationProvider(basicLoginSecurityProvider())
                .authenticationProvider(jwtAuthenticationProvider());

    }

}
