package com.server.sso.shared;

import com.server.sso.auth.AuthResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;


public class AuthResponseException {

  public static ResponseEntity<AuthResponse> responseBaseOnErrorStatus(HttpStatus httpStatus,String message){
    return ResponseEntity.status(httpStatus).body(AuthResponse.builder()
        .status(httpStatus)
        .data(null)
        .message(message)
        .path(null)
        .accessToken(null)
        .build());
  }
}
