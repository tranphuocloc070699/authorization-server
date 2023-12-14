package com.server.sso.user;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
@RequiredArgsConstructor
public class UserDataAccess {
  private final UserRepository userRepository;

  public Optional<User> findByEmail(String email){
    return userRepository.findByEmail(email);
  }

  public  User save(User newUser) {
    return userRepository.save(newUser);
  }
}
