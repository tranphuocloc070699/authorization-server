package com.server.sso.auth;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.*;

@Service
@RequiredArgsConstructor
public class AuthService {

  private final UserDataAccess userDataAccess;

//  private final PasswordEncoder passwordEncoder;
//  private final AuthenticationManager authenticationManager;
  private final HttpServletRequest httpServletRequest;

  @Value("${application.security.jwt.refresh-token.expiration}")
  private int refreshExpiration;

  @Value("${application.security.jwt.refresh-token.name}")
  private String refreshTokenName;

  /* === Signup Route === */
  public ResponseEntity<AuthResponse> signup(AuthSignUpRequest requestUser) {
    return ResponseEntity.status(HttpStatus.OK).body(AuthResponse.builder()
        .accessToken(null)
        .data(null)
        .message("Sign up successfully!")
        .status(HttpStatus.OK)
        .path("/api/v1/auth/signup")
        .build());
  }


  /* === Login Route === */
  public ResponseEntity<AuthResponse> login(AuthLogInRequest requestUser,
                                            HttpServletResponse response) {
    return ResponseEntity.status(HttpStatus.OK).body(AuthResponse.builder()
        .accessToken(null)
        .data(null)
        .message("login successfully!")
        .status(HttpStatus.OK)
        .path("/api/v1/auth/login")
        .build());
  }

  /* === Authenticate Route === */
  public ResponseEntity<AuthResponse> authenticate(HttpServletRequest request,
                                                   HttpServletResponse response) {

    return ResponseEntity.status(HttpStatus.OK).body(AuthResponse.builder()
        .status(HttpStatus.OK)
        .data(null)
        .message("authenticated")
        .path(request.getServletPath())
        .accessToken(null)
        .build());

//    return ResponseEntity.status(HttpStatus.OK).body(new AuthResponse(HttpStatus.OK,null,"authenticated",request.getServletPath()
//        ,null));
  }

  public Optional<String> readServletCookie(HttpServletRequest request, String name) {
    return Arrays.stream(request.getCookies())
        .filter(cookie -> name.equals(cookie.getName()))
        .map(Cookie::getValue)
        .findAny();
  }


  private void writeCookie(User user, HttpServletResponse response) {
//    String refreshToken = jwtService.generateRefreshToken(user);
//    Cookie cookie = new Cookie(refreshTokenName, refreshToken);
//    cookie.setMaxAge(refreshExpiration);
//    cookie.setSecure(false);
//    cookie.setHttpOnly(true);
//    cookie.setPath("/");
//    response.addCookie(cookie);

  }
}
