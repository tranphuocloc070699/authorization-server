package com.server.sso.security.multiFactor;

import dev.samstevens.totp.exceptions.QrGenerationException;

public interface MFATokenManager {
  String generateSecretKey();
  String getQRCode(final String secret,String email) throws QrGenerationException;
  boolean verifyTotp(final String code, final String secret);
}