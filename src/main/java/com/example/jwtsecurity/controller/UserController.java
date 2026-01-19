package com.example.jwtsecurity.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class UserController
{
    @GetMapping("/user/hello")
    public String userProfile()
    {
        return "User Profile Accessed";
    }
}
