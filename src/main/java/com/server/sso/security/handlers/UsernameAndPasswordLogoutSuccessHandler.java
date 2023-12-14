package com.server.sso.security.handlers;

import com.server.sso.security.JwtService;
import com.server.sso.shared.Constant;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.Optional;

@Component
@RequiredArgsConstructor
public class UsernameAndPasswordLogoutSuccessHandler implements LogoutSuccessHandler {
  private final JwtService jwtService;
  private final Constant CONST;

  @Override
  public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication)
      throws IOException, ServletException {
    Optional<String> refreshTokenOptional = jwtService.readServletCookie(request,CONST.JWT_REFRESH_TOKEN_NAME);
    if(refreshTokenOptional.isPresent()){
      jwtService.removeCookie(CONST.JWT_REFRESH_TOKEN_NAME,response);
    }
    response.sendRedirect("/login");
  }
}
