package com.server.sso.shared;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.user.OAuth2User;

import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Optional;

public class TransferData {
  public static byte[] bufferedImageToBytes(BufferedImage bufferedImage) throws IOException, IOException {
    ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();

    // Write BufferedImage to the ByteArrayOutputStream as PNG
    ImageIO.write(bufferedImage, "png", byteArrayOutputStream);

    // Convert the ByteArrayOutputStream to byte[]
    byte[] imageBytes = byteArrayOutputStream.toByteArray();

    // Close the stream
    byteArrayOutputStream.close();

    return imageBytes;
  }


}
