package com.server.sso.auth;

import jakarta.validation.Valid;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;

@Controller("")
public class AuthController {

  @GetMapping("/login")
  public String loginForm(Model model){
    AuthLogInRequest user = new AuthLogInRequest();
    model.addAttribute("user", user);
    return "login";
  }

  @PostMapping("/users/save")
  public String saveUser(@Valid @ModelAttribute("user") AuthLogInRequest user){
    System.out.println(user);
    return "dashboard";
  }
}
