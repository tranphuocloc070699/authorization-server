package com.server.sso.shared;


import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.SuperBuilder;
import org.springframework.http.HttpStatus;

import java.util.Date;

@Data
@AllArgsConstructor
@NoArgsConstructor
@SuperBuilder
public class ResponseObject {
  private Date timestamp;
  private Integer status;
  private Object data;
  private String message;
  private String path;

  public ResponseObject(Integer status, Object data, String message, String path) {
    this.timestamp = new Date();
    this.status = status;
    this.data = data;
    this.message = message;
    this.path = path;
  }
}