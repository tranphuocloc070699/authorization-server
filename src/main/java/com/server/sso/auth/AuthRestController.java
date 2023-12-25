package com.server.sso.auth;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;

@RestController
@RequestMapping("auth")
@RequiredArgsConstructor
public class AuthRestController {

  private final AuthRestService authRestService;
  private final AuthService authService;

  /*
   * Scope: Public [Authenticated]
   * Uses: Get access token from refresh token
   * */
  @GetMapping("authenticate")
  public ResponseEntity<AuthResponse> authenticate(HttpServletRequest request, HttpServletResponse response){
    return authRestService.authenticate(request,response);
  }

  /*
   * Scope: Public [Authenticated]
   * Uses: Get user info from access token
   * Notes: access token store in headers
   * */
  @GetMapping("profile")
  public ResponseEntity<AuthResponse> getProfile(HttpServletRequest request, HttpServletResponse response){
    return authRestService.getProfile(request,response);
  }

  /*
   * Scope: Private [Authenticated]
   * Uses: Toggle Google Multi Factor Authenticate
   * */
  @PutMapping("2fa/toggle")
  public Object enable2Fa(Authentication authentication, Model model){
    return authRestService.toggle2Fa(authentication,model);
  }
}
