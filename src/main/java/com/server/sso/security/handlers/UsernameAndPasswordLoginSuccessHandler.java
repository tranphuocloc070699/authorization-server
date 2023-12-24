package com.server.sso.security.handlers;

import java.io.IOException;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;

import com.server.sso.redis.RedisDataAccess;
import com.server.sso.redis.RedisUser;
import com.server.sso.security.JwtService;
import com.server.sso.user.UserDataAccess;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;

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

      UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
          null,
          null
      );
      authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
      SecurityContextHolder.getContext().setAuthentication(authToken);
      /*When signup, redis user is already exist -> Call api notify new error*/
      System.err.println("Cannot read user from redis : " + redisUser.toString());
    }
    if (redisUser.getIsUsing2FA()) {

      UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
          authentication.getPrincipal(),
          null
      );
      SecurityContextHolder.getContext().setAuthentication(authToken);
      if (redirectUrl != null) {
        response.sendRedirect("/verify-multi-factor?redirectUrl=" + redirectUrl);

      }else{
        response.sendRedirect("/verify-multi-factor");
      }
       return;
    }

    redisUser.setRefreshTokenVersion(redisUser.getRefreshTokenVersion()+1);
    redisDataAccess.save(redisUser);
    jwtService.writeCookie(redisUser.getRefreshTokenVersion(),authentication.getName(),response);

    response.sendRedirect(redirectUrl != null ? redirectUrl : "/dashboard");
  }
}
