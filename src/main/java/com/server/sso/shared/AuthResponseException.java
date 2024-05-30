package com.server.sso.shared;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;


public class AuthResponseException {

  public static ResponseEntity<ResponseObject> responseBaseOnErrorStatus(Integer status,String message){
    return ResponseEntity.status(status).body(ResponseObject.builder()
        .status(status)
        .data(null)
        .message(message)
        .path(null)
        .build());
  }
}
