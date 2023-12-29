package com.server.sso.security.multiFactor;
import java.io.IOException;

import com.server.sso.shared.Constant;
import org.springframework.stereotype.Service;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.WriterException;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.QRCodeWriter;
import com.server.sso.shared.RandomData;
import com.server.sso.shared.TransferData;
import com.warrenstrange.googleauth.GoogleAuthenticator;
import com.warrenstrange.googleauth.GoogleAuthenticatorKey;

import dev.samstevens.totp.code.CodeVerifier;
import dev.samstevens.totp.code.HashingAlgorithm;
import dev.samstevens.totp.exceptions.QrGenerationException;
import dev.samstevens.totp.qr.QrData;
import dev.samstevens.totp.qr.QrGenerator;
import dev.samstevens.totp.secret.SecretGenerator;
import dev.samstevens.totp.util.Utils;
import lombok.RequiredArgsConstructor;

@Service("mfaTokenManager")
@RequiredArgsConstructor
public class DefaultMFATokenManager implements MFATokenManager {

  private final Constant CONST;
  private final MFAService mfaService;

  /*
  * Uses: Generate Secret -> Save to user database
  * */
  @Override
  public String generateSecretKey() {
    return mfaService.secretGenerator.generate();
  }

  /*
  * Uses: Generate QrCode -> client will scan this qr to Google Authenticator App
  * */
  @Override
  public String getQRCode(String secret,String email) throws QrGenerationException {
    QrData data = new QrData.Builder().label(CONST.APP_2FA_LABEL)
        .secret(secret)
        .issuer(email)
        .algorithm(HashingAlgorithm.SHA256)
        .digits(6)
        .period(30)
        .build();
    return Utils.getDataUriForImage(
        mfaService.qrGenerator.generate(data),
        mfaService.qrGenerator.getImageMimeType()
    );
  }

  /*
   * Uses: Verify OTP -> client will enter otp from Google Authenticator App to verify with secret that save in user database
   * */
  @Override
  public boolean verifyTotp(String code, String secret) {
    return mfaService.codeVerifier.isValidCode(code, secret);
  }
}