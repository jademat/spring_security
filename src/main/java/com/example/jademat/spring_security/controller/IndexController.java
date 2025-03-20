package com.example.jademat.spring_security.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class IndexController {

    @GetMapping("/")
    public String index() {
        return "Hello World";
    }
    // User, Admin 접근 가능
    @GetMapping("/user")
    public String user() {
        return "Hello user";
    }
    // Admin만 접근 가능
    @GetMapping("/admin")
    public String admin() {
        return "Hello admin";
    }
}
