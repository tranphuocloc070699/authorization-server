package com.server.sso.security;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Map;
import java.util.stream.Collectors;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfiguration {


  @Bean
  public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
    httpSecurity
        .csrf(AbstractHttpConfigurer::disable)
        .cors(httpSecurityCorsConfigurer -> httpSecurityCorsConfigurer.configurationSource(corsConfigurationSource()))
        .authorizeHttpRequests(
            auth -> auth.requestMatchers("/oauth2/**","/login/**", "/login/*",
                "/signup", "/signup/save",
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
//              if(!request.getParameter("redirectUrl").isEmpty()){
//                response.sendRedirect(request.getParameter("redirectUrl"));
//              }else{
//                response.sendRedirect("/dashboard");
//              }
              String redirectUrl = (String) request.getSession().getAttribute("redirectUrl");
//              System.out.println("redirectUrl:" + redirectUrl);
              if (redirectUrl!=null) {
                response.sendRedirect(redirectUrl);
              }else{
                response.sendRedirect("/dashboard");
              }
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
        .oauth2Login(oauth2Login ->
            oauth2Login
                .loginPage("/login")
                .loginProcessingUrl("/login/oauth2/code/google")

                .successHandler((request,response,authentication) ->{
                  String redirectUrl = (String) request.getSession().getAttribute("redirectUrl");
                  if (redirectUrl!=null) {
                    response.sendRedirect(redirectUrl);
                  }
                })
                .failureHandler((request, response, exception) -> {
                  request.getSession().setAttribute("loginError", exception.getMessage());
                  System.err.println("Oauth2 login error: " + exception.getMessage() );
                  response.sendRedirect("/login?error");
                })
        );
//        .sessionManagement(session ->
//                    session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
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


  @Bean
//  @Transactional(propagation = Propagation.REQUIRED, rollbackFor = Exception.class)
  public UserDetailsService userDetailsService() {
    return new UserDetailsService() {
      @Override
      public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        GrantedAuthority userAuthority = new SimpleGrantedAuthority("ROLE_USER");
        return new User(username,passwordEncoder().encode("123"), Collections.singleton(userAuthority));
      }
    };
  }
  @Bean
  public AuthenticationProvider authenticationProvider() {
    DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
    authProvider.setUserDetailsService(userDetailsService());
    authProvider.setPasswordEncoder(passwordEncoder());
    return authProvider;
  }
  @Bean
  public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
    return config.getAuthenticationManager();
  }
  @Bean
  public PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder(10, new SecureRandom());
  }

//  @Bean
//  public WebSecurityCustomizer webSecurityCustomizer() {
//    return (web) -> web.ignoring().requestMatchers("/auth/**");
//  }
}
