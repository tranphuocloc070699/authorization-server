package com.server.sso.shared;


import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

@Component
public class Constant {

  @Value("${application.security.jwt.refresh-token.name}")
  public String JWT_REFRESH_TOKEN_NAME= "";

  @Value("${application.security.jwt.secret-key}")
  public String JWT_SECRET_KEY;

  @Value("${application.security.jwt.expiration}")
  public Integer JWT_ACCESS_TOKEN_EXPIRE;

  @Value("${application.security.jwt.refresh-token.expiration}")
  public Integer JWT_REFRESH_TOKEN_EXPIRE;

  public ArrayList<String> PUBLIC_ROUTES = new ArrayList<>(List.of("/login","/signup"));




}
