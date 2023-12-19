package com.server.sso.security.handlers;

import com.server.sso.redis.RedisDataAccess;
import com.server.sso.redis.RedisUser;
import com.server.sso.security.JwtService;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class UsernameAndPasswordLoginSuccessHandler implements AuthenticationSuccessHandler {
  private final JwtService jwtService;
  private final RedisDataAccess redisDataAccess;
  @Override
  public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication)
      throws IOException, ServletException {
    String redirectUrl = (String) request.getSession().getAttribute("redirectUrl");

    RedisUser redisUser = redisDataAccess.findRedisUserByEmail(authentication.getName());
    if(redisUser==null){
      /*When signup, redis user is already exist -> Call api notify new error*/
      System.err.println("Cannot read user from redis : " + redisUser.toString());
    }
    redisUser.setRefreshTokenVersion(redisUser.getRefreshTokenVersion()+1);
    jwtService.writeCookie(redisUser.getRefreshTokenVersion(),authentication.getName(),response);

    response.sendRedirect(redirectUrl != null ? redirectUrl : "/dashboard");
  }
}
