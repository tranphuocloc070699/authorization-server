package com.server.sso.security;

import java.security.SecureRandom;
import java.util.Optional;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import com.server.sso.user.User;
import com.server.sso.user.UserDataAccess;

import lombok.RequiredArgsConstructor;


/*This class implement to prevent
* Relying upon circular references is discouraged and they are prohibited by default
* */
@Configuration
@RequiredArgsConstructor
public class AppConfiguration {
  private final UserDataAccess userDataAccess;
  @Bean
//  @Transactional(propagation = Propagation.REQUIRED, rollbackFor = Exception.class)
  public UserDetailsService userDetailsService() {
    return username -> {
      Optional<User> userExisting = userDataAccess.findByEmail(username);
      if(userExisting.isPresent()){
        System.out.println("password: " + userExisting.get().getPassword());
        return new org.springframework.security.core.userdetails.User(username,userExisting.get().getPassword(), userExisting.get().getAuthorities());
      }
      throw new UsernameNotFoundException("user with email ["+username+"] not found");
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
}
