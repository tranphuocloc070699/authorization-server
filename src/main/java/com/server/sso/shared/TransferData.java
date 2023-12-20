package com.server.sso.shared;

import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

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
