package ws.moor;

import com.google.common.io.BaseEncoding;
import com.google.gson.JsonObject;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;

/**
 * An implementation of the client's encryption formats (see crypto.js) that is independent of the
 * browser, to verify what the client writes.
 */
final class EncryptionFormat {

  private EncryptionFormat() {}

  /** @return a key's raw secret, or null if the passphrase does not match */
  static byte[] unwrapSecret(String passphrase, JsonObject encryption) throws GeneralSecurityException {
    String algorithm;
    int iterations;
    switch (encryption.get("algorithm").getAsString()) {
      case "PBKDF2_SHA512_210000_AES_256_CBC_HMAC_SHA256":
        algorithm = "PBKDF2WithHmacSHA512";
        iterations = 210000;
        break;
      case "PBKDF2_SHA1_AES_256_CBC_HMAC_SHA256":
        algorithm = "PBKDF2WithHmacSHA1";
        iterations = 1000;
        break;
      default:
        throw new IllegalArgumentException(encryption.toString());
    }
    // the JDK's PBKDF2 encodes the passphrase as UTF-8, like the client
    byte[] key = SecretKeyFactory.getInstance(algorithm)
        .generateSecret(new PBEKeySpec(passphrase.toCharArray(), bytes(encryption, "iv"), iterations, 256))
        .getEncoded();
    try {
      return decryptBytes(key, encryption);
    } catch (GeneralSecurityException e) {
      return null;
    }
  }

  static String decrypt(byte[] rawSecret, JsonObject value) throws GeneralSecurityException {
    if (!value.get("algorithm").getAsString().equals("AES_256_CBC_HMAC_SHA256")) {
      throw new IllegalArgumentException(value.toString());
    }
    return new String(decryptBytes(rawSecret, value), StandardCharsets.UTF_8);
  }

  private static byte[] decryptBytes(byte[] key, JsonObject value) throws GeneralSecurityException {
    byte[] iv = bytes(value, "iv");
    Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
    cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
    byte[] cleartext = cipher.doFinal(bytes(value, "ciphertext"));

    Mac mac = Mac.getInstance("HmacSHA256");
    mac.init(new SecretKeySpec(key, "HmacSHA256"));
    mac.update(iv);
    if (!MessageDigest.isEqual(mac.doFinal(cleartext), bytes(value, "signature"))) {
      throw new GeneralSecurityException("signature does not match");
    }
    return cleartext;
  }

  private static byte[] bytes(JsonObject value, String field) {
    return BaseEncoding.base64().decode(value.get(field).getAsString());
  }
}
