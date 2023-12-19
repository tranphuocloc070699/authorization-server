package com.server.sso.security.multiFactor;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;

import java.io.Serializable;

@AllArgsConstructor
@Getter
@Setter
public class MfaTokenData implements Serializable {

  private String qrCode;
  private String mfaCode;
  //getter and setter
}