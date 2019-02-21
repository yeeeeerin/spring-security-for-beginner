package com.example.springsecurityguide.controller;

import com.example.springsecurityguide.Service.MemberService;
import com.example.springsecurityguide.domain.Member;
import org.springframework.beans.factory.annotation.Autowired;
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
}
