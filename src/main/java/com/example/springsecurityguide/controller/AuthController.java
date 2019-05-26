package com.example.springsecurityguide.controller;

import com.example.springsecurityguide.Service.MemberService;
import com.example.springsecurityguide.domain.Member;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class AuthController {

    private final MemberService memberService;

    @PostMapping("/signUp")
    public String signUp(@RequestBody Member member){
        memberService.singUp(member);
        return "ok";
    }
}
