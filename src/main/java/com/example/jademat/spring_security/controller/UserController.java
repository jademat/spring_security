package com.example.jademat.spring_security.controller;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

@Slf4j
@RequiredArgsConstructor
@Configuration
@RequestMapping("/member")
public class UserController {

    @GetMapping("/login")
    public String login() {
        return "views/login";
    }
}
