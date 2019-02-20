package com.example.springsecurityguide.domain;

import lombok.Getter;

@Getter
public enum  MemberRole {

    ADMIN("ROLE_ADMIN"), USER("ROLE_USER");
    
    private String roleName;

    MemberRole(String roleName) {
        this.roleName = roleName;
    }

}
