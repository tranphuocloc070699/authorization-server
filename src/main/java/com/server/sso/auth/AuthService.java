package com.server.sso.auth;

import com.server.sso.exception.customs.ForbiddenException;
import com.server.sso.exception.customs.UnAuthenticateException;
import com.server.sso.redis.RedisRepository;
import com.server.sso.security.JwtService;
import com.server.sso.shared.AuthResponseException;
import com.server.sso.shared.Constant;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.stereotype.Service;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;

import java.util.Collections;
import java.util.List;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class AuthService {

  private final UserDataAccess userDataAccess;
  private final JwtService jwtService;
  private final PasswordEncoder passwordEncoder;
  private final RedisRepository redisRepository;
  private final Constant CONST;
  /* === Authenticate Route === */
  public ResponseEntity<AuthResponse> authenticate(HttpServletRequest request,
                                                   HttpServletResponse response) {
    try {
      Optional<String> refreshTokenOptional = jwtService.readServletCookie(request, CONST.JWT_REFRESH_TOKEN_NAME);
      if (refreshTokenOptional.isEmpty()) throw new ForbiddenException("Refresh token not found");
      String refreshToken = refreshTokenOptional.get();
      String userEmail = jwtService.extractUsername(refreshToken);
      if (userEmail == null) throw new UnAuthenticateException("Cannot extract username from this token");

      Optional<User> userExisting = userDataAccess.findByEmail(userEmail);
      if (userExisting.isEmpty()) throw new UnAuthenticateException("User with email [" + userEmail + "] not found");

      boolean isTokenValid = jwtService.isTokenValid(refreshToken, userExisting.get());
      if(!isTokenValid) throw new UnAuthenticateException("Token invalid");

      return ResponseEntity.status(HttpStatus.OK).body(AuthResponse.builder()
          .status(HttpStatus.OK)
          .data(userExisting.get())
          .message("authenticated")
          .path(request.getServletPath())
          .accessToken(jwtService.generateToken(userExisting.get()))
          .build());
    } catch (ForbiddenException e) {
      return AuthResponseException.responseBaseOnErrorStatus(HttpStatus.FORBIDDEN, e.getMessage());
    }
    catch (UnAuthenticateException e) {
      return AuthResponseException.responseBaseOnErrorStatus(HttpStatus.UNAUTHORIZED, e.getMessage());
    }
  }

  public String loginView(Authentication authentication, HttpSession session, String redirectUrl) {
    if (authentication != null && authentication.isAuthenticated()) {
      return "redirect:/dashboard";
    }
    if (redirectUrl != null) {
      session.setAttribute("redirectUrl", redirectUrl);
    }
    return "login";
  }

  public String signupView(Authentication authentication, Model model) {
    if (authentication != null && authentication.isAuthenticated()) {
      return "redirect:/dashboard";
    }

    AuthSignUpRequest user = new AuthSignUpRequest();
    model.addAttribute("user", user);
    return "signup";
  }

  public String dashboardView(Authentication authentication, Model model) {
    if (authentication != null) {
      model.addAttribute("name", authentication.getName() != null ? authentication.getName() : "unknown");
    } else {
      model.addAttribute("name", "authentication null");
    }
    return "dashboard";
  }

  public String signup(Authentication authentication, HttpServletRequest request, HttpServletResponse response,
                       HttpSession httpSession, BindingResult result,
                       AuthSignUpRequest user) {
    try {
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
      User userSaved = userDataAccess.save(newUser);
      if (authentication == null) {
        GrantedAuthority userAuthority = new SimpleGrantedAuthority(Role.USER.name());
        List<GrantedAuthority> authorities = Collections.singletonList(userAuthority);

        UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
            newUser,
            null,
            authorities
        );
        authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
        SecurityContextHolder.getContext().setAuthentication(authToken);
        httpSession.setAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY,
            SecurityContextHolder.getContext());

        RedisUser redisUser = RedisUser.builder()
            .id(userSaved.getId())
            .name(userSaved.getName())
            .email(userSaved.getEmail())
            .createdAt(userSaved.getCreatedAt())
            .updatedAt(userSaved.getUpdatedAt())
            .build();
        redisRepository.save(redisUser);
        jwtService.writeCookie(newUser, response);
      }
      return "redirect:/dashboard";
    } catch (RuntimeException e) {
      System.err.println("saveUser Exception :" + e.getMessage());
      throw new RuntimeException(e.getMessage());
    }
  }
}
