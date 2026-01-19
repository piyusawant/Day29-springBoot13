package com.example.jwtsecurity.security;

import com.example.jwtsecurity.entity.User;
import com.example.jwtsecurity.repository.UserRepository;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Component
public class DataLoader
{
    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @PostConstruct
    public void loadUser()
    {
        if(userRepository.findByUsername("admin").isEmpty())
        {
            User user = new User();
            user.setUsername("admin");

            user.setPassword(passwordEncoder.encode("admin123"));
            user.setRole("ROLE_ADMIN");
            userRepository.save(user);
        }
    }


}
