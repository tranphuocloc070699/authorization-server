package com.server.sso.user;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
@Getter
public enum Permission {

  ADMIN_READ("admin:read"),
  ADMIN_UPDATE("admin:update"),
  ADMIN_CREATE("admin:create"),
  ADMIN_DELETE("admin:delete");


  private final String permission;
}