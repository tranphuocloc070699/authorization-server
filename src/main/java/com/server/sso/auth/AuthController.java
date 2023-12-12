package com.server.sso.auth;

import jakarta.servlet.http.HttpSession;
import jakarta.validation.Valid;
import org.springframework.boot.autoconfigure.neo4j.Neo4jProperties;
import org.springframework.data.repository.query.Param;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;

@Controller("")
public class AuthController {

//  @GetMapping("/login")
//  public String loginForm(Model model){
//    AuthLogInRequest user = new AuthLogInRequest();
//    model.addAttribute("user", user);
//    return "login";
//  }

  @GetMapping("/login")
  public String login(@Param("redirectUrl")String redirectUrl, Model model, HttpSession session) {
    if(redirectUrl!=null){
      session.setAttribute("redirectUrl",redirectUrl);
//      model.addAttribute("redirectUrl",redirectUrl);
    }
    return "login";
  }

  @GetMapping("/logout")
  public String logout() {
    return "logout";
  }

  @GetMapping("/signup")
  public String signupForm(Model model){
    AuthSignUpRequest user = new AuthSignUpRequest();
    model.addAttribute("user", user);
    return "signup";
  }

  @GetMapping("/dashboard")
  public String dashboard(Authentication authentication,Model model){

model.addAttribute("name",authentication.getName()!=null ? authentication.getName() : "unknown");

    return "dashboard";
  }

  @PostMapping("/users/save")
  public String saveUser( @ModelAttribute("user") AuthLogInRequest user,BindingResult result){
    if (result.hasErrors()) {
      return "login"; // Return back to the form with error messages
    }
    System.out.println("user: " + user);
    return "dashboard";
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
