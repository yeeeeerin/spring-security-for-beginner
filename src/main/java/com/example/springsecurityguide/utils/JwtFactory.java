package com.example.springsecurityguide.utils;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.example.springsecurityguide.domain.SecurityMember;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;


@Slf4j
@Component
public class JwtFactory {

    private static String SECRET = "TheSecret";

    /*
     * 유저의 권한정보로 토큰을 만듬(claim에는 여러 정보가 올 수 있다.)
     * */
    public String generateToken(SecurityMember securityMember) {
        String token;

        token = JWT.create()
                .withIssuer("yerin")
                .withClaim("EMAIL", securityMember.getUsername())
                .sign(Algorithm.HMAC256(SECRET));

        log.info("token -- "+token);

        return token;

    }

}
