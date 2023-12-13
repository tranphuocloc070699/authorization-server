package com.server.sso.exception.customs;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;
@ResponseStatus(HttpStatus.NOT_FOUND)
public class NotFoundException extends RuntimeException {
  private final String path;

  public NotFoundException(String message, String path) {
    super(message);
    this.path = path;
  }
}