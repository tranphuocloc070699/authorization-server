package com.server.sso.auth;

import jakarta.validation.Valid;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
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

  @GetMapping("/signup")
  public String signupForm(Model model){
    AuthSignUpRequest user = new AuthSignUpRequest();
    model.addAttribute("user", user);
    return "signup";
  }

  @PostMapping("/users/save")
  public String saveUser(@Valid @ModelAttribute("user") AuthLogInRequest user,BindingResult result){
    if (result.hasErrors()) {
      return "login"; // Return back to the form with error messages
    }
    System.out.println(user);
    return "login";
  }

  @PostMapping("/signup/save")
  public String saveUser(@Valid @ModelAttribute("user") AuthSignUpRequest user, BindingResult result){
    if (result.hasErrors()) {
      return "signup"; // Return back to the form with error messages
    }
    System.out.println(user);
    return "signup";
  }
}
