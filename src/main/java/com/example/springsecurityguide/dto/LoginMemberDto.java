package com.example.springsecurityguide.dto;

import lombok.Data;

@Data
public class LoginMemberDto {
    private String email;
    private String password;
}
