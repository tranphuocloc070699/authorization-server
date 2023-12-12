package com.server.sso.auth;

import jakarta.servlet.http.HttpSession;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.neo4j.Neo4jProperties;
import org.springframework.data.repository.query.Param;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;

import java.util.Collections;

@Controller("")
@RequiredArgsConstructor
public class AuthController {

//  @GetMapping("/login")
//  public String loginForm(Model model){
//    AuthLogInRequest user = new AuthLogInRequest();
//    model.addAttribute("user", user);
//    return "login";
//  }

  private final UserDataAccess userDataAccess;
  private final PasswordEncoder passwordEncoder;

  @GetMapping("/login")
  public String login(@Param("redirectUrl") String redirectUrl, Model model, HttpSession session) {
    if (redirectUrl != null) {
      session.setAttribute("redirectUrl", redirectUrl);
//      model.addAttribute("redirectUrl",redirectUrl);
    }
    return "login";
  }

  @GetMapping("/logout")
  public String logout() {
    return "logout";
  }

  @GetMapping("/signup")
  public String signupForm(Model model) {
    AuthSignUpRequest user = new AuthSignUpRequest();
    model.addAttribute("user", user);
    return "signup";
  }

  @GetMapping("/dashboard")
  public String dashboard(Authentication authentication, Model model) {

    model.addAttribute("name", authentication.getName() != null ? authentication.getName() : "unknown");

    return "dashboard";
  }

//  @PostMapping("/users/save")
//  public String saveUser( @ModelAttribute("user") AuthLogInRequest user,BindingResult result){
//    if (result.hasErrors()) {
//      return "login"; // Return back to the form with error messages
//    }
//    System.out.println("user: " + user);
//    return "dashboard";
//  }


  @PostMapping("/users/save")
  public String saveUser(@Valid @ModelAttribute("user") AuthSignUpRequest user, BindingResult result) {
    if (result.hasErrors()) {
      return "signup"; // Return back to the form with error messages
    }

    String passwordEncoded = passwordEncoder.encode(user.getPassword());
    User newUser = User.builder()
        .email(user.getEmail())
        .role(Role.USER)
        .provider(Provider.LOCAL)
        .name(user.getName())
        .password(passwordEncoded)
        .build();

    userDataAccess.save(newUser);

    if (SecurityContextHolder.getContext().getAuthentication() == null) {
      GrantedAuthority userAuthority = new SimpleGrantedAuthority(Role.USER.name());
      org.springframework.security.core.userdetails.User userDetails = new org.springframework.security.core.userdetails.User(
          user.getEmail(), passwordEncoded,
          Collections.singleton(userAuthority));
      UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
          userDetails,
          null,
          userDetails.getAuthorities()
      );
      SecurityContextHolder.getContext().setAuthentication(authToken);
    }


    return "redirect:/dashboard";
  }
}
