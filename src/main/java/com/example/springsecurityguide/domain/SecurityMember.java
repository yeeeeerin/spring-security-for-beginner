package com.example.springsecurityguide.domain;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;

import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.stream.Collectors;


public class SecurityMember extends User {


    public SecurityMember(String email, String password, Collection<? extends GrantedAuthority> authorities) {
        super(email, password, authorities);
    }

    public static SecurityMember getMemberDetails(Member member) {
        return new SecurityMember(member.getEmail(),member.getPassword(),parseAuthorities(member.getRole()));
    }

    private static List<SimpleGrantedAuthority> parseAuthorities(MemberRole role) {
        return Arrays.asList(role).stream()
                .map(r -> new SimpleGrantedAuthority(r.getRoleName()))
                .collect(Collectors.toList());
    }

    public static List<SimpleGrantedAuthority> parseAuthorities(String role) {

        MemberRole memberRole = Arrays.stream(MemberRole.values())
                .filter(r -> r.getRoleName().equalsIgnoreCase(role))
                .findFirst()
                .orElseThrow(() -> new NoSuchElementException("권한이 없습니다"));

        return parseAuthorities(memberRole);
    }

    public String getRole(){
        return getAuthorities().stream().findFirst().get().getAuthority();
    }
}
