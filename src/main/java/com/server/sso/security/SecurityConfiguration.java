package com.server.sso.security;

import com.server.sso.security.filters.JwtAuthenticationFilter;
import com.server.sso.shared.Constant;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfiguration {

  private final JwtAuthenticationFilter jwtAuthenticationFilter;
  private final JwtService jwtService;
  private final Constant CONST;
  @Bean
  public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
    httpSecurity
        .csrf(AbstractHttpConfigurer::disable)
        .cors(httpSecurityCorsConfigurer -> httpSecurityCorsConfigurer.configurationSource(corsConfigurationSource()))
        .authorizeHttpRequests(
            auth -> auth.requestMatchers("/oauth2/**", "/login/**",
                "/signup/**",
                "/users/**",
                "/auth/**",
                "/swagger" + "-ui/**", "/v3" + "/api" + "-docs/**")
                .permitAll()
                .anyRequest()
                .authenticated())

        .formLogin(form -> form
            .loginPage("/login")
            .loginProcessingUrl("/login")
            .permitAll()
            .successHandler(((request, response, authentication) -> {
              String redirectUrl = (String) request.getSession().getAttribute("redirectUrl");
              response.sendRedirect(redirectUrl != null ? redirectUrl : "/dashboard");
            }))
            .failureHandler((request, response, exception) -> {
              Map<String, String[]> parameterMap = request.getParameterMap();
              String parameterString = parameterMap.entrySet()
                  .stream()
                  .map(entry -> entry.getKey() + "=" + Arrays.toString(entry.getValue()))
                  .collect(Collectors.joining(", "));

              System.err.println("Login failed. Parameters: " + parameterString);
              request.getSession().setAttribute("loginError", exception.getMessage());
              response.sendRedirect(request.getContextPath() + "/login?error");
            }))
        .logout(logoutForm -> logoutForm
            .logoutUrl("/logout")
            .logoutSuccessHandler((request, response, authentication) ->{
              Optional<String> refreshTokenOptional = jwtService.readServletCookie(request,CONST.JWT_REFRESH_TOKEN_NAME);
              if(refreshTokenOptional.isPresent()){
                jwtService.removeCookie(CONST.JWT_REFRESH_TOKEN_NAME,response);
              }
              response.sendRedirect("/login");
        }))
        .oauth2Login(oauth2Login ->
            oauth2Login
                .loginPage("/login")
                .loginProcessingUrl("/login/oauth2/code/google")
                .successHandler((request,response,authentication) ->{
                  String redirectUrl = (String) request.getSession().getAttribute("redirectUrl");
                  System.out.println(authentication);
                  response.sendRedirect(redirectUrl != null ? redirectUrl : "/dashboard");
                })
                .failureHandler((request, response, exception) -> {
                  request.getSession().setAttribute("loginError", exception.getMessage());
                  System.err.println("Oauth2 login fail: " + exception.getMessage());
                  response.sendRedirect("/login?error");
                })
        )
        .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);
    return httpSecurity.build();
  }

  public CorsConfigurationSource corsConfigurationSource() {
    CorsConfiguration configuration = new CorsConfiguration();
    configuration.addAllowedOrigin("*");
    configuration.addAllowedMethod("*");
    configuration.addAllowedHeader("*");
    configuration.setAllowCredentials(true);

    UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
    source.registerCorsConfiguration("/**", configuration);

    return source;
  }




//  @Bean
//  public WebSecurityCustomizer webSecurityCustomizer() {
//    return (web) -> web.ignoring().requestMatchers("/auth/**");
//  }
}
