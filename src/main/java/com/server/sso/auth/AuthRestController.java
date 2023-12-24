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

  private final AuthService authService;

  @GetMapping("authenticate")
  public ResponseEntity<AuthResponse> authenticate(HttpServletRequest request, HttpServletResponse response){
    return authService.authenticate(request,response);
  }

  @PutMapping("2fa/toggle")
  public Object enable2Fa(Authentication authentication, Model model){
    return authService.toggle2Fa(authentication,model);
  }

  @PostMapping("verify2fa")
  public Object verify2Fa(@RequestParam("numberValue") String value,Authentication authentication,Model model) {
    return authService.verifyTest2Fa(authentication,value,model);
  }

  @GetMapping("profile")
  public ResponseEntity<AuthResponse> getProfile(HttpServletRequest request, HttpServletResponse response){
    return authService.getProfile(request,response);
  }
}
