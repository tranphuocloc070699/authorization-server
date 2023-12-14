package com.server.sso.security.handlers;

import com.server.sso.user.Provider;
import com.server.sso.user.Role;
import com.server.sso.user.User;
import com.server.sso.user.UserDataAccess;
import com.server.sso.redis.RedisDataAccess;
import com.server.sso.redis.RedisUser;
import com.server.sso.security.JwtService;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.Optional;

@Component
@RequiredArgsConstructor
public class OAuth2LoginSuccessHandler implements AuthenticationSuccessHandler {
  private final JwtService jwtService;
  private final RedisDataAccess redisDataAccess;
  private final UserDataAccess userDataAccess;

  @Override
  public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication)
      throws IOException, ServletException {
    String redirectUrl = (String) request.getSession().getAttribute("redirectUrl");
    /*
     * If user exist in redis -> user already signup
     * Case 1 : already signup
     *        -> login
     * Case 2 : not signup
     *        -> like username and password signup
     * */
    OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();
    String name = oAuth2User.getAttribute("name");
    String email = oAuth2User.getAttribute("email");

    Optional<User> userExisted = userDataAccess.findByEmail(email);

    if (userExisted.isPresent()) {
      /*Login case*/
      RedisUser redisUser = redisDataAccess.findRedisUserByEmail(email);
      if (redisUser == null) {
        /*When signup, redis user is already exist -> Call api notify new error*/
        System.err.println("Cannot read user from redis : " + redisUser.toString());
      }
      redisUser.setRefreshTokenVersion(redisUser.getRefreshTokenVersion() + 1);
      redisDataAccess.save(redisUser);
      jwtService.writeCookie(redisUser.getRefreshTokenVersion(), email, response);
    } else {
      /*Signup case*/
      User newUser = User.builder()
          .email(email)
          .role(Role.USER)
          .provider(Provider.GOOGLE)
          .name(name)
          .password(null)
          .build();
      User userSaved = userDataAccess.save(newUser);

      RedisUser redisUser = RedisUser.builder()
          .id(userSaved.getId())
          .name(userSaved.getName())
          .email(userSaved.getEmail())
          .provider(userSaved.getProvider())
          .role(userSaved.getRole())
          .refreshTokenVersion(0)
          .createdAt(userSaved.getCreatedAt())
          .updatedAt(userSaved.getUpdatedAt())
          .build();
      redisDataAccess.save(redisUser);
      jwtService.writeCookie(redisUser.getRefreshTokenVersion(), newUser.getEmail(), response);

    }
    response.sendRedirect(redirectUrl != null ? redirectUrl : "/dashboard");
  }
}


