package com.example.springsecurityguide.utils;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Getter
@Setter
@Component
@ConfigurationProperties(prefix = "jwt", ignoreInvalidFields = true)
public class JwtSettings {

    private String tokenIssuer;

    private String tokenSigningKey;

}
