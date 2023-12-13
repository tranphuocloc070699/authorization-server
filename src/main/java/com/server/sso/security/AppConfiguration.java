package com.server.sso.security;

import com.server.sso.auth.User;
import com.server.sso.auth.UserDataAccess;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.security.SecureRandom;
import java.util.Optional;


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
    return new UserDetailsService() {
      @Override
      public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Optional<User> userExisting = userDataAccess.findByEmail(username);
        if(userExisting.isPresent()){
          return new org.springframework.security.core.userdetails.User(username,userExisting.get().getPassword(), userExisting.get().getAuthorities());
        }
        throw new UsernameNotFoundException("user with email "+username+" not found");
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
}
