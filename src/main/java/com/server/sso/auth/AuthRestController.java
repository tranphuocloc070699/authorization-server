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
  @PostMapping("signup")
  public ResponseEntity<AuthResponse> signup(@Valid @RequestBody AuthSignUpRequest requestUser
                                    ){
    return authService.signup(requestUser);
  }

  @PostMapping("login")
  public ResponseEntity<AuthResponse> login(@Valid @RequestBody AuthLogInRequest requestUser,
                                            HttpServletResponse response){
  return authService.login(requestUser,response);
  }

  @GetMapping("authenticate")
  public ResponseEntity<AuthResponse> authenticate(HttpServletRequest request, HttpServletResponse response){
    return authService.authenticate(request,response);
  }
}
