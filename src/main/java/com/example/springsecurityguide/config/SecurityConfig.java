package com.example.springsecurityguide.config;

import com.example.springsecurityguide.filter.BasicLoginProcessingFilter;
import com.example.springsecurityguide.provider.BasicLoginSecurityProvider;
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

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    BasicLoginSecurityProvider basicLoginSecurityProvider;

    @Bean
    public PasswordEncoder getPasswordEncoder() {
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
    }

    @Bean
    protected BasicLoginProcessingFilter basicLoginProcessingFilter() throws Exception {
        BasicLoginProcessingFilter filter = new BasicLoginProcessingFilter("/login");
        filter.setAuthenticationManager(super.authenticationManagerBean());
        return filter;
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) {
        auth
                .authenticationProvider(this.basicLoginSecurityProvider);
    }



}
