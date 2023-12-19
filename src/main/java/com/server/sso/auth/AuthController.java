package com.server.sso.auth;


import com.server.sso.security.JwtService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.neo4j.Neo4jProperties;
import org.springframework.data.repository.query.Param;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;

import java.security.Principal;
import java.util.Collections;
import java.util.List;

@Controller("")
@RequiredArgsConstructor
public class AuthController {

  private final AuthService authService;


  @GetMapping("/login")
  public String loginView(@Param("redirectUrl") String redirectUrl, Model model, HttpSession session, Principal principal,
                       Authentication authentication) {
    return authService.loginView(authentication,session,redirectUrl);
  }

  @GetMapping("/signup")
  public String signupView(Model model,Authentication authentication) {
   return authService.signupView(authentication,model);
  }

  @GetMapping("/dashboard")
  public String dashboardView(Authentication authentication, Model model) {
    return authService.dashboardView(authentication,model);
  }
  @PostMapping("/users/save")
  public String saveUser(@Valid @ModelAttribute("user") AuthSignUpRequest user, BindingResult result,
                         Authentication authentication, HttpSession httpSession, HttpServletRequest request,
                         HttpServletResponse response) {
    return authService.signup(authentication,request,response,httpSession,result,user);
  }


}
