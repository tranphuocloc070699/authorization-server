package com.server.sso.auth;

import com.server.sso.shared.ResponseObject;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.NoArgsConstructor;
import lombok.experimental.SuperBuilder;
import org.springframework.http.HttpStatus;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@EqualsAndHashCode(callSuper = true)
@Data
@AllArgsConstructor
@NoArgsConstructor
@SuperBuilder
public class AuthResponse extends ResponseObject {
  private String accessToken;
  public AuthResponse( HttpStatus status, Object data, String message, String path, String accessToken) {
    super(status, data, message, path);
    this.accessToken = accessToken;

    System.out.println("AuthResponse constructor");
  }
}