package com.example.springsecurityguide.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

@Data
public class LoginMemberDto {

    String email;

    String password;
}
