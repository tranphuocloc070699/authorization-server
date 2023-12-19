package com.server.sso.auth;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.ui.Model;
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

  @GetMapping("2fa")
  public ResponseEntity<AuthResponse> toggle2Fa(Authentication authentication, Model model){
    System.out.println(authentication.getName());
    return ResponseEntity.status(HttpStatus.OK).body(AuthResponse.builder()
        .status(HttpStatus.OK)
        .data(null)
        .message("authenticated")
        .path(null)
        .accessToken(null)
        .build());
  }
}
