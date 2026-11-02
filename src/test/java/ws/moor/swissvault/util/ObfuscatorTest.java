/*
 * Copyright 2012 Patrick Moor <patrick@moor.ws>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ws.moor.swissvault.util;

import org.junit.Test;

import javax.crypto.spec.SecretKeySpec;
import java.util.Random;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertThrows;

public class ObfuscatorTest {
  @Test
  public void randomLongs() {
    long seed = System.currentTimeMillis();
    System.out.printf("random seed: %d\n", seed);
    Random rnd = new Random(seed);

    byte[] key = new byte[8];
    rnd.nextBytes(key);
    Obfuscator obfuscator = new Obfuscator(new SecretKeySpec(key, "Blowfish"));

    for (int i = 0; i < 1000; i++) {
      long secret = rnd.nextLong();
      String obfuscated = obfuscator.obfuscateLong(secret);
      long unobfuscated = obfuscator.unobfuscateLong(obfuscated);
      assertThat(unobfuscated).isEqualTo(secret);
    }
  }

  @Test
  public void specificLongs() {
    assertObfuscatesTo(Long.MIN_VALUE, "8e3a7a307f0ffa3c");
    assertObfuscatesTo(Long.MIN_VALUE + 1, "630e8401eb2613e2");

    assertObfuscatesTo(-1, "a30969c2022555c8");
    assertObfuscatesTo(0, "1bfed93fc7d99b9e");
    assertObfuscatesTo(1, "6949d135d37d9f63");

    assertObfuscatesTo(Long.MAX_VALUE - 1, "e06d5a0d3b827a69");
    assertObfuscatesTo(Long.MAX_VALUE, "39727ae9766d1cc7");
  }

  @Test
  public void shortEncryptions() {
    assertObfuscatesTo(2090197856513702069L, "012cc47e690bc3c9");
    assertObfuscatesTo(-7610100052787030355L, "00b2d1e7dbd2b7c7");
    assertObfuscatesTo(-6306291253572087852L, "000bafb16f27334a");
    assertObfuscatesTo(-1133199824324347252L, "00009cec374c1381");
  }

  @Test
  public void unobfuscateLong_invalidInputsThrowIllegalArgumentException() {
    Obfuscator obfuscator = new Obfuscator(new SecretKeySpec(new byte[] {1, 2, 3, 4, 5, 6, 7, 8}, "Blowfish"));
    String validHex = obfuscator.obfuscateLong(0L); // "1bfed93fc7d99b9e"

    // null
    assertThrows(IllegalArgumentException.class, () -> obfuscator.unobfuscateLong(null));

    // empty string
    assertThrows(IllegalArgumentException.class, () -> obfuscator.unobfuscateLong(""));

    // short hex strings
    assertThrows(IllegalArgumentException.class, () -> obfuscator.unobfuscateLong("01234567"));
    assertThrows(IllegalArgumentException.class, () -> obfuscator.unobfuscateLong("1bfed93fc7d99b9"));

    // multi-block hex strings
    assertThrows(IllegalArgumentException.class, () -> obfuscator.unobfuscateLong(validHex + validHex));
    assertThrows(IllegalArgumentException.class, () -> obfuscator.unobfuscateLong(validHex + validHex + validHex));

    // uppercase hex characters
    assertThrows(IllegalArgumentException.class, () -> obfuscator.unobfuscateLong(validHex.toUpperCase()));

    // non-hex characters of length 16
    assertThrows(
        IllegalArgumentException.class,
        () -> obfuscator.unobfuscateLong("0123456789abcdef".replace('f', 'g')));
  }

  private void assertObfuscatesTo(long original, String expectedObfuscation) {
    Obfuscator obfuscator = new Obfuscator(new SecretKeySpec(new byte[] {1, 2, 3, 4, 5, 6, 7, 8}, "Blowfish"));
    assertThat(obfuscator.obfuscateLong(original)).isEqualTo(expectedObfuscation);
    assertThat(obfuscator.unobfuscateLong(expectedObfuscation)).isEqualTo(original);
  }
}
