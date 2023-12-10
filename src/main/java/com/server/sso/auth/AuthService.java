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

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class AuthService {

  private final UserDataAccess userDataAccess;

  private final PasswordEncoder passwordEncoder;
  private final JwtService jwtService;
  private final AuthenticationManager authenticationManager;
  private final HttpServletRequest httpServletRequest;

  @Value("${application.security.jwt.refresh-token.expiration}")
  private int refreshExpiration;

  @Value("${application.security.jwt.refresh-token.name}")
  private String refreshTokenName;

  /* === Signup Route === */
  public ResponseEntity<AuthResponse> signup(AuthSignUpDto requestUser, HttpServletResponse response) {
    if (requestUser.getRole() != null && !requestUser.getRole().equals(Role.USER)) {
      throw new ConflictException("Role invalid", httpServletRequest.getServletPath());
    }
    Optional<User> optionalUser = this.userDataAccess.findByEmail(requestUser.getEmail());
    if (optionalUser.isPresent()) {
      throw new ConflictException("user [%s] already exist".formatted(requestUser.getEmail()), httpServletRequest.getServletPath());
    }

    Optional<User> responseUser = this.userDataAccess.save(User.builder()
        .name(requestUser.getName())
        .email(requestUser.getEmail())
        .password(passwordEncoder.encode(requestUser.getPassword()))
        .role(Role.USER)
        .build());
    if (responseUser.isEmpty()) {
      return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(AuthResponse.builder()
          .accessToken("")
          .data(null)
          .timestamp(new Date())
          .message("cannot save user")
          .status(HttpStatus.INTERNAL_SERVER_ERROR)
          .path("/api/v1/auth/signup")
          .build());
    }

    String accessToken = jwtService.generateToken(responseUser.get());
    Map<String, Object> data = new HashMap<>();
    data.put("user", Optional.of(responseUser));
    writeCookie(responseUser.get(), response);
    return ResponseEntity.status(HttpStatus.OK).body(AuthResponse.builder()
        .accessToken(accessToken)
        .data(data)
        .message("Sign up successfully!")
        .status(HttpStatus.OK)
        .path("/api/v1/auth/signup")
        .build());
  }


  /* === Login Route === */
  public ResponseEntity<AuthResponse> login(AuthLogInDto requestUser,
                                            HttpServletResponse response) {
    authenticationManager.authenticate(
        new UsernamePasswordAuthenticationToken(
            requestUser.getEmail(),
            requestUser.getPassword()
        )
    );

    Optional<User> optionalUser = this.userDataAccess.findByEmail(requestUser.getEmail());
    if (optionalUser.isEmpty()) {
      throw new UnAuthenticateException("user with email [" + requestUser.getEmail() + "] not found");
    }

    Map<String, Object> data = new HashMap<>();
    data.put("user", Optional.of(optionalUser));
    writeCookie(optionalUser.get(), response);
    String accessToken = jwtService.generateToken(optionalUser.get());
    return ResponseEntity.status(HttpStatus.OK).body(AuthResponse.builder()
        .accessToken(accessToken)
        .data(data)
        .message("login successfully!")
        .status(HttpStatus.OK)
        .path("/api/v1/auth/login")
        .build());
  }

  /* === Authenticate Route === */
  public ResponseEntity<AuthResponse> authenticate(HttpServletRequest request,
                                                   HttpServletResponse response) {
    Optional<String> refreshToken = readServletCookie(request, refreshTokenName);
    if (refreshToken.isEmpty()) {
      throw new UnAuthenticateException("Cookie not found");
    }
    String userEmail = jwtService.extractUsername(refreshToken.get());
    Optional<User> userDetails = this.userDataAccess.findByEmail(userEmail);
    if (userDetails.isEmpty()) {
      throw new UnAuthenticateException("user with email [" + userEmail + "] not found");
    }
    if (!jwtService.isTokenValid(refreshToken.get(), userDetails.get())) {
      throw new UnAuthenticateException("Refresh token invalid");
    }

    writeCookie(userDetails.get(), response);
    String accessToken = jwtService.generateToken(userDetails.get());
    Map<String, Object> data = new HashMap<>();
    data.put("user", Optional.of(userDetails));

    return ResponseEntity.status(HttpStatus.OK).body(AuthResponse.builder()
        .accessToken(accessToken)
        .data(data)
        .timestamp(new Date())
        .message("authenticated")
        .status(HttpStatus.OK)
        .path(request.getServletPath())
        .build());
  }

  public Optional<String> readServletCookie(HttpServletRequest request, String name) {
    return Arrays.stream(request.getCookies())
        .filter(cookie -> name.equals(cookie.getName()))
        .map(Cookie::getValue)
        .findAny();
  }


  private void writeCookie(User user, HttpServletResponse response) {
    String refreshToken = jwtService.generateRefreshToken(user);
    Cookie cookie = new Cookie(refreshTokenName, refreshToken);
    cookie.setMaxAge(refreshExpiration);
    cookie.setSecure(false);
    cookie.setHttpOnly(true);
    cookie.setPath("/");
    response.addCookie(cookie);

  }
}
