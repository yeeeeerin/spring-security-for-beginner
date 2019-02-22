package com.example.springsecurityguide.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

@Data
public class LoginMemberDto {
    @JsonProperty(value = "email")
    String email;
    @JsonProperty(value = "password")
    String password;
}
