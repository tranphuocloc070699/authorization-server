package com.server.sso.security.handlers;

import java.io.IOException;
import java.util.Optional;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.stereotype.Component;

import com.server.sso.security.JwtService;
import com.server.sso.shared.Constant;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;

@Component
@RequiredArgsConstructor
public class UsernameAndPasswordLogoutSuccessHandler implements LogoutSuccessHandler {
  private final JwtService jwtService;
  private final Constant CONST;

  @Override
  public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication)
      throws IOException, ServletException {
    /*
     * Case: LOGOUT
     * - Check cookie
     *    - Exist: Remove cookie
     * - Check SecurityContextHolder
     *    - True: clear -> for next signup will not be conflict
     * */
    Optional<String> refreshTokenOptional = jwtService.readServletCookie(request,CONST.JWT_REFRESH_TOKEN_NAME);
    if(refreshTokenOptional.isPresent()){
      jwtService.removeCookie(CONST.JWT_REFRESH_TOKEN_NAME,response);
    }
    if(SecurityContextHolder.getContext()!=null){
      UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
          null,null
      );
      authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
      SecurityContextHolder.getContext().setAuthentication(authToken);
    }
    response.sendRedirect("/login");
  }
}
