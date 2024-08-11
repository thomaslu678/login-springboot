package com.foodfinder.controller;

import jakarta.annotation.PostConstruct;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

@Controller
@CrossOrigin
public class HomeController {

    @PostConstruct
    void init() {
    }

    @GetMapping("/")
    @ResponseBody // for returning string instead of template with that name
    public String home(Principal principal) {
        return "Hello".concat(principal.getName());
    }

    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/admin")
    public String admin() {
        return "Hello, Admin!";
    }

    @GetMapping("/login")
    public String login() {
        return "login";
    }
}
