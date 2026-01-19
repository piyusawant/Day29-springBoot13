package com.example.jwtsecurity.security;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.*;

@Component
public class JwtUtil
{
    private final SecretKey key = Keys.secretKeyFor(SignatureAlgorithm.HS256);

    private static final long EXPIRATION = 1000 * 60 * 60; // 1hr


    //Generate Token
    public String generateToken(String username,String role)
    {
        return Jwts.builder()
                .setSubject(username)
                .claim("role", role)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + EXPIRATION))
                        .signWith(key)
                .compact();
    }

    //Extract Username
    public String extractUsername(String token)
    {
        return Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody()
                .getSubject();
    }

    //Extract Role
    public String extractRole(String token)
    {
        return Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody()
                .get("role", String.class);
    }

    //Validate Token
    public boolean validateToken(String token)
    {
        try
        {
            Jwts.parserBuilder().setSigningKey(key)
                    .build()
                    .parseClaimsJws(token);
            return true;
        }catch(Exception e) {
            return false;
        }
    }

}
