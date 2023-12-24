package com.server.sso.security.multiFactor;
import java.io.IOException;

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
  private final SecretGenerator secretGenerator = new SecretGenerator() {
    @Override
    public String generate() {
      return RandomData.generateRandomBase32();
    }
  };
  private final QrGenerator qrGenerator = new QrGenerator() {
    @Override
    public String getImageMimeType() {
      return "image/png";
    }

    @Override
    public byte[] generate(QrData qrData) throws QrGenerationException {
//      try {
//        // Example: Generating a simple QR code with ZXing library
//        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
//        BitMatrix bitMatrix = new QRCodeWriter().encode(qrData.getSecret(), BarcodeFormat.QR_CODE, 200, 200);
//        MatrixToImageWriter.writeToStream(bitMatrix, "PNG", outputStream);
//        return outputStream.toByteArray();
//      } catch (WriterException | IOException e) {
//        throw new QrGenerationException("Error generating QR code", e);
//      }
      try {
      QRCodeWriter writer = new QRCodeWriter();
      String issuer = "SSO";
      String email = "user@example.com";
      String secret = qrData.getSecret();
      String otpAuthUri = "otpauth://totp/" + qrData.getIssuer() + "?secret=" + secret + "&issuer=" + issuer;
        BitMatrix  matrix = writer.encode(otpAuthUri, BarcodeFormat.QR_CODE, 300, 300);
        return TransferData.bufferedImageToBytes(MatrixToImageWriter.toBufferedImage(matrix));
      } catch (WriterException | IOException e ) {
        throw new QrGenerationException("Error generating QR code", e);
      }
    }
  };
  private final CodeVerifier codeVerifier = new CodeVerifier() {
    @Override
    public boolean isValidCode(String code, String secret) {
//      GoogleAuthenticatorConfig config = new GoogleAuthenticatorConfig.GoogleAuthenticatorConfigBuilder()
//          .setWindowSize(5) // Adjust the window size to a larger value, default is 3
//          .setTimeStepSizeInMillis(30000) // Default is 30 seconds, adjust as needed
//          .build();
      GoogleAuthenticator gAuth = new GoogleAuthenticator();
      // Create a GoogleAuthenticatorKey using the user's secret key
      GoogleAuthenticatorKey key = new GoogleAuthenticatorKey.Builder(secret).build();
      long allowedTimeDrift =  30 * 1000;
      // Verify the user-entered TOTP
      boolean isCodeValid = gAuth.authorize(key.getKey(), Integer.parseInt(code),System.currentTimeMillis()+allowedTimeDrift);
      return isCodeValid;
    }
  };

  @Override
  public String generateSecretKey() {
    return secretGenerator.generate();
  }

  @Override
  public String getQRCode(String secret,String email) throws QrGenerationException {
    QrData data = new QrData.Builder().label("MFA")
        .secret(secret)
        .issuer("SSO:"+email)
        .algorithm(HashingAlgorithm.SHA256)
        .digits(6)
        .period(30)
        .build();
    return Utils.getDataUriForImage(
        qrGenerator.generate(data),
        qrGenerator.getImageMimeType()
    );
  }

  @Override
  public boolean verifyTotp(String code, String secret) {
    return codeVerifier.isValidCode(code, secret);
  }
}