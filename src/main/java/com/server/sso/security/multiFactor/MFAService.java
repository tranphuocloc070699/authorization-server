package com.server.sso.security.multiFactor;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.WriterException;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.QRCodeWriter;
import com.server.sso.shared.Constant;
import com.server.sso.shared.RandomData;
import com.server.sso.shared.TransferData;
import com.warrenstrange.googleauth.GoogleAuthenticator;
import com.warrenstrange.googleauth.GoogleAuthenticatorKey;
import dev.samstevens.totp.code.CodeVerifier;
import dev.samstevens.totp.exceptions.QrGenerationException;
import dev.samstevens.totp.qr.QrData;
import dev.samstevens.totp.qr.QrGenerator;
import dev.samstevens.totp.secret.SecretGenerator;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.io.IOException;

@Service
@RequiredArgsConstructor
public class MFAService {
  private final Constant CONST;
  public  SecretGenerator secretGenerator = RandomData::generateRandomBase32;
  public  QrGenerator qrGenerator = new QrGenerator() {
    @Override
    public String getImageMimeType() {
      return "image/png";
    }

    @Override
    public byte[] generate(QrData qrData) throws QrGenerationException {
      try {
        QRCodeWriter writer = new QRCodeWriter();
        String issuer = CONST.APP_2FA_ISSUER;
        String secret = qrData.getSecret();
        String otpAuthUri = "otpauth://totp/" + qrData.getIssuer() + "?secret=" + secret + "&issuer=" + issuer;
        BitMatrix matrix = writer.encode(otpAuthUri, BarcodeFormat.QR_CODE, 300, 300);
        return TransferData.bufferedImageToBytes(MatrixToImageWriter.toBufferedImage(matrix));
      } catch (WriterException | IOException e ) {
        throw new QrGenerationException("Error generating QR code", e);
      }
    }
  };

  public CodeVerifier codeVerifier = (code, secret) -> {
    GoogleAuthenticator gAuth = new GoogleAuthenticator();
    // Create a GoogleAuthenticatorKey using the user's secret key
    GoogleAuthenticatorKey key = new GoogleAuthenticatorKey.Builder(secret).build();
    long allowedTimeDrift =  30 * 1000;
    // Verify the user-entered TOTP
    return gAuth.authorize(key.getKey(), Integer.parseInt(code),System.currentTimeMillis()+allowedTimeDrift);
  };
}
