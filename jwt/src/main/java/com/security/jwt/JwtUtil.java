package com.security.jwt;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import javax.crypto.SecretKey;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Date;

@Component
public class JwtUtil {

    @Value("${jwt.secret}")
    private String secretKey;

    @Value("${jwt.expiration_access}")
    private long expiration;




    private SecretKey getSigningKey() {
        return Keys.hmacShaKeyFor(secretKey.getBytes());   //HMAC 알고리즘일 때는 SecretKey로 return하기.
    }

    // Access Token 생성
    public String   createAccessToken(String username) {
        return Jwts.builder()
            .subject(username) // ✅ setSubject() -> subject()
            .issuedAt(new Date())
            .expiration(new Date(System.currentTimeMillis() + expiration))
            .signWith(getSigningKey()) // ✅ SignatureAlgorithm.HS256 대신 Jwts.SIG.HS256 사용
            .compact();
    }




    //토큰에서 username 추출
    public String extractUsername(String token) {
        return Jwts.parser()
            .verifyWith(getSigningKey())  // 0.12.3버전에서는 verifyWith에 Key말고 SecretKey가 와야한다.
            .build()
            .parseSignedClaims(token)
            .getPayload()
            .getSubject();
    }

    //토큰에서 인증여부 확인.
    public boolean validateToken(String token) {
        try {
            Claims claims = Jwts.parser()
                .verifyWith(getSigningKey())  // ✅ 서명 검증
                .build()
                .parseSignedClaims(token)    // ✅ JWT 파싱
                .getPayload();               // ✅ claims(토큰 정보) 추출
            return true;
        } catch (JwtException | IllegalArgumentException e) {
            return false;
        }
    }
}

//jjwt 버전에 따라 구현방식이 다르다. 현재는 0.12.3 버전.
