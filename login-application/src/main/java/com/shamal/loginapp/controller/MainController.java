package com.shamal.loginapp.controller;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;


@Controller

public class MainController {
    @RequestMapping("/")
    public String home(){
        return "redirect:/login";
    }
    @GetMapping("/login")
    public String showLoginForm() {

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || authentication instanceof AnonymousAuthenticationToken) {
            return "login";
        }

        return "redirect:/dashboard";
    }
    @GetMapping("/dashboard")
    public String dashboard(){
        return "dashboard";
    }
}
