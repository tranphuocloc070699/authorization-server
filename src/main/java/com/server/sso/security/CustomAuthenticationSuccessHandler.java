package com.server.sso.security;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
public class CustomAuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

  @Override
  protected void handle(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException,
      ServletException {
    // Log the loggedIn user
    System.out.println("LoggedIn user " + authentication.getPrincipal());

    // Access and print query parameters
    String queryString = request.getQueryString();
    System.out.println("Query Params: " + queryString);

    // Redirect to Google with the original query parameters
    response.sendRedirect("https://www.google.com?" + queryString);
  }
}