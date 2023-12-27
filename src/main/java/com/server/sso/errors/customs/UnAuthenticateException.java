package com.server.sso.errors.customs;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.UNAUTHORIZED)
public class UnAuthenticateException extends RuntimeException{
  public UnAuthenticateException(String message) {
    super(message);
  }
}