package com.example.jwtsecurity.controller;

import com.example.jwtsecurity.dto.AuthRequest;
import com.example.jwtsecurity.dto.AuthResponse;
import com.example.jwtsecurity.entity.User;
import com.example.jwtsecurity.repository.UserRepository;
import com.example.jwtsecurity.security.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class AuthController
{
    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private JwtUtil jwtUtil;

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody AuthRequest request)
    {
        try {
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword())
            );
        } catch (Exception ex) {
            return ResponseEntity.status(401).body("Invalid username or password");
        }

        User user = userRepository
                .findByUsername(request.getUsername())
                .orElseThrow(() -> new RuntimeException("User not found"));

        String token = jwtUtil.generateToken(user.getUsername(), user.getRole());

        return ResponseEntity.ok(new AuthResponse(token));
    }
}

