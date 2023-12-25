package com.server.sso.security;

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

import com.server.sso.security.filters.JwtAuthenticationFilter;
import com.server.sso.security.handlers.OAuth2LoginFailureHandler;
import com.server.sso.security.handlers.OAuth2LoginSuccessHandler;
import com.server.sso.security.handlers.UsernameAndPasswordLoginFailureHandler;
import com.server.sso.security.handlers.UsernameAndPasswordLoginSuccessHandler;
import com.server.sso.security.handlers.UsernameAndPasswordLogoutSuccessHandler;
import com.server.sso.shared.Constant;

import lombok.RequiredArgsConstructor;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfiguration {

  private final JwtAuthenticationFilter jwtAuthenticationFilter;
  private final UsernameAndPasswordLoginSuccessHandler usernameAndPasswordLoginSuccessHandler;
  private final UsernameAndPasswordLoginFailureHandler usernameAndPasswordLoginFailureHandler;
  private final UsernameAndPasswordLogoutSuccessHandler usernameAndPasswordLogoutSuccessHandler;
  private final OAuth2LoginSuccessHandler oAuth2LoginSuccessHandler;
  private final OAuth2LoginFailureHandler oAuth2LoginFailureHandler;

  @Bean
  public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
    httpSecurity
        .csrf(AbstractHttpConfigurer::disable)
        .cors(httpSecurityCorsConfigurer -> httpSecurityCorsConfigurer.configurationSource(corsConfigurationSource()))
        .authorizeHttpRequests(
            auth -> auth.requestMatchers("/oauth2/**",
                    "/login/**",
                    "/signup/**",
                    "/verify-multi-factor/**",
                    "/users/**",
                    "/auth/**",
                    "/signup-instruction/**",
                    "/signup-success/**",
                    "/verify-multi-factor/**")
                .permitAll()
                .requestMatchers("/css/**",
                    "/js/**",
                    "/images/**",
                    "/webjars/**",
                    "/fontawesome/**",
                    "/webfonts/**").permitAll()
                .anyRequest()
                .authenticated())

        .formLogin(form -> form
            .loginPage("/login")
            .loginProcessingUrl("/login")
            .permitAll()
            .successHandler(usernameAndPasswordLoginSuccessHandler)
            .failureHandler(usernameAndPasswordLoginFailureHandler))
        .logout(logoutForm -> logoutForm
            .logoutUrl("/logout")
            .logoutSuccessHandler(usernameAndPasswordLogoutSuccessHandler))
        .oauth2Login(oauth2Login ->
            oauth2Login
                .loginPage("/login")
                .loginProcessingUrl("/login/oauth2/code/google")
                .successHandler(oAuth2LoginSuccessHandler)
                .failureHandler(oAuth2LoginFailureHandler)
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

  /*
  @Bean
  public WebSecurityCustomizer webSecurityCustomizer() {
    return (web) -> web.ignoring().requestMatchers("/auth/**");
  }*/
}
