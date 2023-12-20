package com.server.sso.shared;

public class ValidateData {
  public static boolean isValidLong(String code) {
    try {
      Long.parseLong(code);
    } catch (NumberFormatException e) {
      return false;
    }
    return true;
  }
}
