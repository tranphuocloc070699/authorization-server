package com.server.sso.auth;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Repository;

@Repository
@RequiredArgsConstructor
public class UserDataAccess {
  private final UserRepository authRepository;

}
