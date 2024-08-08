package com.foodfinder;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import java.security.Principal;

@Controller
public class HomeController {

    @GetMapping("/")
    @ResponseBody // for returning string instead of template with that name
    public String home(Principal principal) {
        return "Hello".concat(principal.getName());
    }

    @GetMapping("/login")
    public String login() {
        return "login";
    }
}
