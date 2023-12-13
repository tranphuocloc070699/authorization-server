package com.server.sso.security.filters;

import com.server.sso.auth.AuthService;
import com.server.sso.security.JwtService;
import com.server.sso.shared.Constant;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.security.core.userdetails.UserDetails;
import java.io.IOException;
import java.util.Optional;

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
    try{
      if(request.getHeader("X-Rest-Api")!=null){

      }else{
        Optional<String> refreshTokenOptional = jwtService.readServletCookie(request,CONST.JWT_REFRESH_TOKEN_NAME);
        if(refreshTokenOptional.isPresent()){
          String refreshToken = refreshTokenOptional.get();
          String userEmail = jwtService.extractUsername(refreshToken);
          if(userEmail!=null && SecurityContextHolder.getContext().getAuthentication()==null) {
            UserDetails userDetails = this.userDetailsService.loadUserByUsername(userEmail);
            if (userDetails!=null && jwtService.isTokenValid(refreshToken, userDetails)) {
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
    }catch (UsernameNotFoundException exception){
      jwtService.removeCookie(CONST.JWT_REFRESH_TOKEN_NAME,response);
    }
    filterChain.doFilter(request,response);

  }
}