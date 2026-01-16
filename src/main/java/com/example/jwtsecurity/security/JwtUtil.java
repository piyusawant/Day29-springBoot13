package com.example.jwtsecurity.security;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.util.*;

@Component
public class JwtUtil
{
    private static final String SECRET_KEY =
            "hserkvkhskjmasjdbadsecretkeystronegstkeyauthentication123";
    private static final long EXPIRATION_TIME = 60 * 60 * 1000; // 1hr


    //Generate Token
    public String generateToken(String username,String role)
    {
        return Jwts.builder()
                .setSubject(username)
                .claim("role","ROLE_" + role)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + EXPIRATION_TIME))
                .signWith(Keys.hmacShaKeyFor(SECRET_KEY.getBytes(StandardCharsets.UTF_8)),
                        SignatureAlgorithm.HS256)
                .compact();
    }

    //Validate Token
    public boolean validateToken(String token)
    {
        try
        {
            Jwts.parserBuilder()
                    .setSigningKey(SECRET_KEY.getBytes(StandardCharsets.UTF_8))
                    .build()
                    .parseClaimsJws(token);
            return true;
        }catch(ExpiredJwtException e)
        {
            System.out.println("Token Expired");
        }catch(JwtException e)
        {
            System.out.println("Invalid Token");
        }
        return false;
    }

    //Extract Username
    public String extractUsername(String token)
    {
        return extractClaims(token).getSubject();
    }
    //Extract Roles
    public String extractRole(String token)
    {
        return extractClaims(token).get("role",String.class);
    }

    private Claims extractClaims(String token)
    {
        return Jwts.parserBuilder()
                .setSigningKey(SECRET_KEY.getBytes(StandardCharsets.UTF_8))
                .build()
                .parseClaimsJws(token)
                .getBody();
    }
}
