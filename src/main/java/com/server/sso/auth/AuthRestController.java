package com.server.sso.auth;

import com.server.sso.exception.customs.ForbiddenException;
import com.server.sso.exception.customs.UnAuthenticateException;
import com.server.sso.shared.AuthResponseException;
import com.server.sso.user.User;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.data.repository.query.Param;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.util.Optional;

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
  public Object toggle2Fa(Authentication authentication, Model model){
    return authService.test2Fa(authentication,model);
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
