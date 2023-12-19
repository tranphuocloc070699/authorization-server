package com.server.sso.auth;

import com.server.sso.exception.customs.ForbiddenException;
import com.server.sso.exception.customs.UnAuthenticateException;
import com.server.sso.redis.RedisDataAccess;
import com.server.sso.redis.RedisUser;
import com.server.sso.security.JwtService;
import com.server.sso.security.multiFactor.DefaultMFATokenManager;
import com.server.sso.security.multiFactor.MfaTokenData;
import com.server.sso.shared.AuthResponseException;
import com.server.sso.shared.Constant;
import com.server.sso.shared.RandomData;
import com.server.sso.user.Provider;
import com.server.sso.user.Role;
import com.server.sso.user.User;
import com.server.sso.user.UserDataAccess;

import dev.samstevens.totp.exceptions.QrGenerationException;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.ServletOutputStream;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
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
  private final Constant CONST;
  private final RedisDataAccess redisDataAccess;
  private final DefaultMFATokenManager defaultMFATokenManager;
  /* === Authenticate Route === */
  public ResponseEntity<AuthResponse> authenticate(HttpServletRequest request,
                                                   HttpServletResponse response) {
    try {
      Optional<String> refreshTokenOptional = jwtService.readServletCookie(request, CONST.JWT_REFRESH_TOKEN_NAME);
      if (refreshTokenOptional.isEmpty()) throw new ForbiddenException("Refresh token not found");
      String refreshToken = refreshTokenOptional.get();
      String userEmail = jwtService.extractUsername(refreshToken);
      if (userEmail == null) throw new UnAuthenticateException("Cannot extract username from this token");

      /*Validate from redis db*/
      Integer refreshTokenVersion = jwtService.extractClaim(refreshToken,claims -> claims.get("refreshTokenVersion",Integer.class));
      RedisUser redisUserExisted = redisDataAccess.findRedisUserByEmail(userEmail);
      if(redisUserExisted==null) throw new UnAuthenticateException("[Redis] User with email [\" + userEmail + \"] not found\"");
      if(refreshTokenVersion==null || !refreshTokenVersion.equals(redisUserExisted.getRefreshTokenVersion())) throw new UnAuthenticateException("[Redis] refresh token not match");

      /*Validate user existing in db*/
      Optional<User> userExisting = userDataAccess.findByEmail(userEmail);
      if (userExisting.isEmpty()) throw new UnAuthenticateException("[Database] User with email [" + userEmail + "] not found");

      /*Validate token expire and user email match from token and db */
      boolean isTokenValid = jwtService.isTokenValid(refreshToken, userExisting.get());
      if(!isTokenValid) throw new UnAuthenticateException("Token invalid");

      /*
      All thing good.
      increase cookie version
      */
      redisUserExisted.setRefreshTokenVersion(redisUserExisted.getRefreshTokenVersion()+1);
      redisDataAccess.save(redisUserExisted);
      jwtService.writeCookie(redisUserExisted.getRefreshTokenVersion(),userExisting.get().getEmail(), response);

      return ResponseEntity.status(HttpStatus.OK).body(AuthResponse.builder()
          .status(HttpStatus.OK)
          .data(userExisting.get())
          .message("authenticated")
          .path(request.getServletPath())
          .accessToken(jwtService.generateToken(userExisting.get().getEmail()))
          .build());
    } catch (ForbiddenException  e) {
      return AuthResponseException.responseBaseOnErrorStatus(HttpStatus.FORBIDDEN, e.getMessage());
    }
    catch (UnAuthenticateException | JwtException e) {
      return AuthResponseException.responseBaseOnErrorStatus(HttpStatus.UNAUTHORIZED, e.getMessage());
    }
    catch (RuntimeException e) {
      System.err.println("[authenticate] internal server error :" + e.getMessage());
      return AuthResponseException.responseBaseOnErrorStatus(HttpStatus.INTERNAL_SERVER_ERROR, e.getMessage());
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
      model.addAttribute("name", authentication.getName() != null ? getName(authentication) : "unknown");
      if(authentication.getName()!=null){
        RedisUser redisUser = redisDataAccess.findRedisUserByEmail(getName(authentication));
        List<RedisUser> redisUserList = redisDataAccess.findAll();
        model.addAttribute("userList",redisUserList);
        model.addAttribute("user",redisUser);
      }
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
          .isUsing2FA(true)
          .secret(defaultMFATokenManager.generateSecretKey())
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
            .provider(userSaved.getProvider())
            .role(userSaved.getRole())
            .refreshTokenVersion(0)
            .isUsing2FA(userSaved.getIsUsing2FA())
            .secret(userSaved.getSecret())
            .createdAt(userSaved.getCreatedAt())
            .updatedAt(userSaved.getUpdatedAt())

            .build();
        redisDataAccess.save(redisUser);
        jwtService.writeCookie(redisUser.getRefreshTokenVersion(),newUser.getEmail(), response);
      }
      return "redirect:/dashboard";
    } catch (RuntimeException e) {
      System.err.println("saveUser Exception :" + e.getMessage());
      throw new RuntimeException(e.getMessage());
    }
  }

  private String getName(Authentication authentication) {
    return Optional.of(authentication)
        .filter(OAuth2AuthenticationToken.class::isInstance)
        .map(OAuth2AuthenticationToken.class::cast)
        .map(OAuth2AuthenticationToken::getPrincipal)
        .map(OidcUser.class::cast)
        .map(OidcUser::getEmail)
        .orElseGet(authentication::getName);
  }

  public ResponseEntity<AuthResponse> getProfile(HttpServletRequest request, HttpServletResponse response) {
    try{
      final String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
      final String jwt;
      final String userEmail;
      if(authHeader==null || !authHeader.startsWith("Bearer ")){
        throw new ForbiddenException("token not found");
      }
      jwt = authHeader.substring(7);
      userEmail = jwtService.extractUsername(jwt);
      if(userEmail==null) throw new UnAuthenticateException("Cannot extract email from token");

      Optional<User> userOptional = userDataAccess.findByEmail(userEmail);
      if(userOptional.isEmpty()) throw new UnAuthenticateException("User not found with this token");

      return ResponseEntity.status(HttpStatus.OK).body(AuthResponse.builder()
          .status(HttpStatus.OK)
          .data(userOptional.get())
          .message("get profile successfully!")
          .path(request.getServletPath())
          .accessToken(jwtService.generateToken(userOptional.get().getEmail()))
          .build());
    }
    catch (ForbiddenException  e) {
      return AuthResponseException.responseBaseOnErrorStatus(HttpStatus.FORBIDDEN, e.getMessage());
    }
    catch (UnAuthenticateException | JwtException e) {
      return AuthResponseException.responseBaseOnErrorStatus(HttpStatus.UNAUTHORIZED, e.getMessage());
    }
    catch (RuntimeException e) {
      System.err.println("[authenticate] internal server error :" + e.getMessage());
      return AuthResponseException.responseBaseOnErrorStatus(HttpStatus.INTERNAL_SERVER_ERROR, e.getMessage());
    }
  }

  public  Object test2Fa(Authentication authentication, Model model) {
    try {
      System.out.println(authentication.getName());
      if(authentication==null || authentication.getName()==null) throw new ForbiddenException("authentication null");
      String userEmail = getName(authentication);
      if(userEmail==null) throw new UnAuthenticateException("Cannot extract userEmail ["+authentication.getName()+"] from " +
          "authentication");

      Optional<User> userExisting = userDataAccess.findByEmail(userEmail);
      if (userExisting.isEmpty()) throw new UnAuthenticateException("[Database] User with email [" + userEmail + "] not found");

      /*All thing good*/
//      userExisting.get().setIsUsing2FA(!userExisting.get().getIsUsing2FA());
//      userDataAccess.save(userExisting.get());


      MfaTokenData data = new MfaTokenData(defaultMFATokenManager.getQRCode(userExisting.get().getSecret()),
          userExisting.get().getSecret());

      return ResponseEntity.status(HttpStatus.OK).body(AuthResponse.builder()
          .status(HttpStatus.OK)
          .data(data)
          .message("authenticated")
          .path(null)
          .accessToken(null)
          .build());
    }  catch (ForbiddenException  e) {
      return AuthResponseException.responseBaseOnErrorStatus(HttpStatus.FORBIDDEN, e.getMessage());
    } catch (QrGenerationException e) {
      throw new RuntimeException(e);
    }
  }

  public Object verifyTest2Fa(Authentication authentication, String value, Model model) {
    if(authentication==null || authentication.getName()==null) throw new ForbiddenException("authentication null");
    String userEmail = getName(authentication);
    if(userEmail==null) throw new UnAuthenticateException("Cannot extract userEmail ["+authentication.getName()+"] from " +
        "authentication");

    Optional<User> userExisting = userDataAccess.findByEmail(userEmail);
    if (userExisting.isEmpty()) throw new UnAuthenticateException("[Database] User with email [" + userEmail + "] not found");

    return defaultMFATokenManager.verifyTotp(value,userExisting.get().getSecret()) ? "Verification successful" : "Verification " +
        "failed";

  }
}
