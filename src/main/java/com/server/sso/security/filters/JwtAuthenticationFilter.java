package com.server.sso.security.filters;

import java.io.IOException;
import java.util.Optional;

import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.server.sso.security.JwtService;
import com.server.sso.shared.Constant;

import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {
  private final JwtService jwtService;
  private final Constant CONST;
  private final UserDetailsService userDetailsService;

  @Override
  protected void doFilterInternal(@NonNull HttpServletRequest request,
                                  @NonNull HttpServletResponse response,
                                  @NonNull FilterChain filterChain) throws ServletException, IOException, JwtException {
    try {
      
      if (request.getHeader("X-Rest-Api") != null) {
        /*Rest Api */
        System.out.println("Rest api calling");
      } else {
        /*
         * Read cookie
         *   - Cookie exist
         *     - True: Check Jwt (extractUsername,isTokenValid)
         *       - Valid: get user from database (loadUserByUsername) & set user to Authenticate
         *   doFilter
         * */
        Optional<String> refreshTokenOptional = jwtService.readServletCookie(request, CONST.JWT_REFRESH_TOKEN_NAME);
        System.out.println("refreshTokenOptional" + refreshTokenOptional.get());
        if (refreshTokenOptional.isPresent()) {
          String refreshToken = refreshTokenOptional.get();
          String userEmail = jwtService.extractUsername(refreshToken);
          if (userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            UserDetails userDetails = this.userDetailsService.loadUserByUsername(userEmail);
            if (userDetails != null && jwtService.isTokenValid(refreshToken, userDetails)) {
              UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                      userDetails,
                      null,
                      userDetails.getAuthorities()
              );
              authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
              SecurityContextHolder.getContext().setAuthentication(authToken);
            }
          }
        }
      }
    } catch (UsernameNotFoundException exception) {
      System.err.println("JwtAuthenticationFilter Exception: " + exception.getMessage());
      jwtService.removeCookie(CONST.JWT_REFRESH_TOKEN_NAME, response);
    } catch (RuntimeException exception) {
      System.err.println("doFilterInternal Exception: " + exception.getMessage());
    }
    filterChain.doFilter(request,response);

  }
}