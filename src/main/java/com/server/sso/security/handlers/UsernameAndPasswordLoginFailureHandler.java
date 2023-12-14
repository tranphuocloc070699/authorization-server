package com.server.sso.security.handlers;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.Arrays;
import java.util.Map;
import java.util.stream.Collectors;

@Component
public class UsernameAndPasswordLoginFailureHandler implements AuthenticationFailureHandler {

  @Override
  public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception)
      throws IOException, ServletException {
    Map<String, String[]> parameterMap = request.getParameterMap();
    String parameterString = parameterMap.entrySet()
        .stream()
        .map(entry -> entry.getKey() + "=" + Arrays.toString(entry.getValue()))
        .collect(Collectors.joining(", "));

    System.err.println("Login failed. Parameters: " + parameterString);
    request.getSession().setAttribute("loginError", exception.getMessage());
    response.sendRedirect(request.getContextPath() + "/login?error");
  }
}
