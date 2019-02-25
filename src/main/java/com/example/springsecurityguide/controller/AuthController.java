package com.example.springsecurityguide.controller;

import com.example.springsecurityguide.Service.MemberService;
import com.example.springsecurityguide.domain.Member;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class AuthController {

    @Autowired
    MemberService memberService;

    @PostMapping("/signUp")
    public String signUp(@RequestBody Member member){
        memberService.singUp(member);
        return "ok";
    }

    @GetMapping("/only_user")
    @PreAuthorize("hasRole('ROLE_USER')")
    public String onlyUser(){
        return "hi user";
    }

    @GetMapping("/only_admin")
    @PreAuthorize("hasRole('ROLE_ADMIN')")
    public String onlyAdmin(){
        return "hi user";
    }
}
