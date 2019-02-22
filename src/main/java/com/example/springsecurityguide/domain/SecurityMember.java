package com.example.springsecurityguide.domain;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

public class SecurityMember extends User {

    public SecurityMember(String username, String password, Collection<? extends GrantedAuthority> authorities) {
        super(username, password, authorities);
    }

    public static SecurityMember getMemberDetails(Member member) {
        return new SecurityMember(member.getEmail(),member.getPassword(),parseAuthorities(member.getRole()));
    }

    private static List<SimpleGrantedAuthority> parseAuthorities(MemberRole role) {
        return Arrays.asList(role).stream()
                .map(r -> new SimpleGrantedAuthority(r.getRoleName()))
                .collect(Collectors.toList());
    }
}
