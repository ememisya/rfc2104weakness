/*
 * POC demonstrating a weakness in RFC-2104
 */
package edu.vt.rfc2104weakness;

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;
import org.cryptacular.util.HashUtil;

/**
 *
 * @author ememisya@vt.edu (Erdem Memisyazici)
 */
public class Application {

  /**
   * HMAC_SHA1 algorithm name.
   */
  private static final String HMAC_SHA1 = "HmacSHA1";

  /**
   * A 65 byte key.
   */
  private static final String KEY = "12345678901234567890123456789012345678901234567890123456789012345";

  /**
   * A block of text to sign.
   */
  private static final String TEXT = "The quick brown fox jumps over the lazy dog";

  /**
   * Displays the demonstration.
   * <p>
   * @param args the command line arguments
   */
  public static void main(final String[] args)
  {
    final byte[] keyBytes = KEY.getBytes(StandardCharsets.UTF_8);
    final byte[] sha1 = HashUtil.sha1(KEY);
    System.out.println("Signed with key:");
    System.out.println(sign(keyBytes, TEXT));
    System.out.println("Signed with hash of key:");
    System.out.println(sign(sha1, TEXT));
  }

  /**
   * Signs the supplied input with {@link #HMAC_SHA1}.
   * <p>
   * @param input Data to sign
   * @param secretKey Key to sign with.
   * <p>
   * @return Signed hash string
   */
  private static String sign(final byte[] secretKey, final String input)
  {
    final SecretKeySpec key = new SecretKeySpec(secretKey, HMAC_SHA1);
    final Mac mac;
    try {
      mac = Mac.getInstance(HMAC_SHA1);
      mac.init(key);
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException("Could not find the HMAC_SHA1 algorithm", e);
    } catch (InvalidKeyException e) {
      throw new IllegalStateException("Invalid key supplied", e);
    }
    return DatatypeConverter.printHexBinary(mac.doFinal(input.getBytes(StandardCharsets.UTF_8)));
  }
}
