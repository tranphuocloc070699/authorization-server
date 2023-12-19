package com.server.sso.shared;

import org.apache.commons.codec.binary.Base32;

public class RandomData {
  public static String generateRandomBase32() {
    byte[] randomBytes = new byte[20]; // You can adjust the length as needed
    new java.security.SecureRandom().nextBytes(randomBytes);

    Base32 base32 = new Base32();

    return base32.encodeAsString(randomBytes);
  }
}
