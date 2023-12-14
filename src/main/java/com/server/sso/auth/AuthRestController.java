package com.server.sso.auth;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("auth")
@RequiredArgsConstructor
public class AuthRestController {

  private final AuthService authService;

  @GetMapping("authenticate")
  public ResponseEntity<AuthResponse> authenticate(HttpServletRequest request, HttpServletResponse response){
    return authService.authenticate(request,response);
  }

  @GetMapping("profile")
  public ResponseEntity<AuthResponse> getProfile(HttpServletRequest request, HttpServletResponse response){
    return authService.getProfile(request,response);
  }
}
