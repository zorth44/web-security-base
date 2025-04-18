package com.zorth.util;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SecureDigestAlgorithm;
import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;

public class JwtTokenUtil {

    // Option 1: Use a longer string (at least 32 characters for 256 bits)
    private static final String SECRET_KEY = "your-256-bit-secret-key-that-is-long-enough-for-security";
    
    // Option 2: Use the JJWT key generator (recommended)
    // private static final SecretKey KEY = Jwts.SIG.HS256.key().build();
    
    private static final long EXPIRATION_TIME = 86400000L; // 过期时间（1天）
    private static final SecureDigestAlgorithm<SecretKey, SecretKey> ALGORITHM = Jwts.SIG.HS256;
    private static final SecretKey KEY = Keys.hmacShaKeyFor(SECRET_KEY.getBytes(StandardCharsets.UTF_8));

    // 生成JWT
    public static String generateToken(String username, String tokenType) {
        return Jwts.builder()
                .claim("tokenType", tokenType)
                .subject(username) // 设置主题
                .issuedAt(new Date()) // 签发时间
                .expiration(new Date(System.currentTimeMillis() + EXPIRATION_TIME)) // 过期时间
                .signWith(KEY, ALGORITHM) // 签名
                .compact();
    }

    public static String getTokenType(String token) {
        return Jwts.parser()
                .verifyWith(KEY)
                .build()
                .parseSignedClaims(token)
                .getPayload()
                .get("tokenType", String.class);
    }

    // 解析JWT 
    public static String getUsernameFromToken(String token) {
        return Jwts.parser()
                .verifyWith(KEY)
                .build()
                .parseSignedClaims(token)
                .getPayload()
                .getSubject();
    }

    // 判断Token是否过期
    public static boolean isTokenExpired(String token) {
        Date expiration = Jwts.parser()
                .verifyWith(KEY)
                .build()
                .parseSignedClaims(token)
                .getPayload()
                .getExpiration();
        return expiration.before(new Date());
    }

}
