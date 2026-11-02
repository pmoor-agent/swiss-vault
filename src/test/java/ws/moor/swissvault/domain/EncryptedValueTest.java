/*
 * Copyright 2026 Patrick Moor <patrick@moor.ws>
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
package ws.moor.swissvault.domain;

import com.google.appengine.api.datastore.Text;
import com.google.common.io.BaseEncoding;
import com.google.gson.JsonArray;
import com.google.gson.JsonNull;
import com.google.gson.JsonObject;
import com.google.gson.JsonPrimitive;
import org.junit.Test;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertThrows;

public class EncryptedValueTest {

  private static final EncryptionAlgorithm ALGORITHM = EncryptionAlgorithm.AES_256_CBC_HMAC_SHA256;
  private static final byte[] VALID_IV = new byte[16];
  private static final byte[] VALID_CIPHERTEXT = "valid ciphertext bytes".getBytes(StandardCharsets.UTF_8);
  private static final byte[] VALID_SIGNATURE = new byte[32];

  static {
    Arrays.fill(VALID_IV, (byte) 0x11);
    Arrays.fill(VALID_SIGNATURE, (byte) 0x22);
  }

  @Test
  public void testConstructor_validArguments() {
    EncryptedValue ev = new EncryptedValue(ALGORITHM, VALID_IV, VALID_CIPHERTEXT, VALID_SIGNATURE);
    assertThat(ev.getAlgorithm()).isEqualTo(ALGORITHM);
    assertThat(ev.getIv()).isEqualTo(VALID_IV);
    assertThat(ev.getCiphertext()).isEqualTo(VALID_CIPHERTEXT);
    assertThat(ev.getSignature()).isEqualTo(VALID_SIGNATURE);
  }

  @Test
  public void testConstructor_maxCiphertextAllowed() {
    byte[] maxCiphertext = new byte[EncryptedValue.MAX_CIPHERTEXT_BYTES];
    Arrays.fill(maxCiphertext, (byte) 0x01);
    EncryptedValue ev = new EncryptedValue(ALGORITHM, VALID_IV, maxCiphertext, VALID_SIGNATURE);
    assertThat(ev.getCiphertext()).hasLength(EncryptedValue.MAX_CIPHERTEXT_BYTES);
  }

  @Test
  public void testConstructor_nullAlgorithm() {
    assertThrows(IllegalArgumentException.class, () ->
        new EncryptedValue(null, VALID_IV, VALID_CIPHERTEXT, VALID_SIGNATURE));
  }

  @Test
  public void testConstructor_invalidIv() {
    assertThrows(IllegalArgumentException.class, () ->
        new EncryptedValue(ALGORITHM, null, VALID_CIPHERTEXT, VALID_SIGNATURE));
    assertThrows(IllegalArgumentException.class, () ->
        new EncryptedValue(ALGORITHM, new byte[0], VALID_CIPHERTEXT, VALID_SIGNATURE));
    assertThrows(IllegalArgumentException.class, () ->
        new EncryptedValue(ALGORITHM, new byte[15], VALID_CIPHERTEXT, VALID_SIGNATURE));
    assertThrows(IllegalArgumentException.class, () ->
        new EncryptedValue(ALGORITHM, new byte[17], VALID_CIPHERTEXT, VALID_SIGNATURE));
  }

  @Test
  public void testConstructor_invalidCiphertext() {
    assertThrows(IllegalArgumentException.class, () ->
        new EncryptedValue(ALGORITHM, VALID_IV, null, VALID_SIGNATURE));
    assertThrows(IllegalArgumentException.class, () ->
        new EncryptedValue(ALGORITHM, VALID_IV, new byte[0], VALID_SIGNATURE));

    byte[] tooLarge = new byte[EncryptedValue.MAX_CIPHERTEXT_BYTES + 1];
    assertThrows(IllegalArgumentException.class, () ->
        new EncryptedValue(ALGORITHM, VALID_IV, tooLarge, VALID_SIGNATURE));
  }

  @Test
  public void testConstructor_invalidSignature() {
    assertThrows(IllegalArgumentException.class, () ->
        new EncryptedValue(ALGORITHM, VALID_IV, VALID_CIPHERTEXT, null));
    assertThrows(IllegalArgumentException.class, () ->
        new EncryptedValue(ALGORITHM, VALID_IV, VALID_CIPHERTEXT, new byte[0]));
    assertThrows(IllegalArgumentException.class, () ->
        new EncryptedValue(ALGORITHM, VALID_IV, VALID_CIPHERTEXT, new byte[31]));
    assertThrows(IllegalArgumentException.class, () ->
        new EncryptedValue(ALGORITHM, VALID_IV, VALID_CIPHERTEXT, new byte[33]));
  }

  @Test
  public void testJsonObjectRoundTrip() {
    EncryptedValue original = new EncryptedValue(ALGORITHM, VALID_IV, VALID_CIPHERTEXT, VALID_SIGNATURE);
    JsonObject json = original.toJsonObject();

    EncryptedValue restored = EncryptedValue.fromJsonObject(json);
    assertThat(restored.getAlgorithm()).isEqualTo(original.getAlgorithm());
    assertThat(restored.getIv()).isEqualTo(original.getIv());
    assertThat(restored.getCiphertext()).isEqualTo(original.getCiphertext());
    assertThat(restored.getSignature()).isEqualTo(original.getSignature());
  }

  @Test
  public void testFromJsonObject_null() {
    assertThrows(IllegalArgumentException.class, () -> EncryptedValue.fromJsonObject(null));
  }

  @Test
  public void testFromJsonObject_missingFields() {
    List<String> fields = List.of("version", "algorithm", "iv", "ciphertext", "signature");
    for (String fieldToOmit : fields) {
      JsonObject json = createValidJsonObject();
      json.remove(fieldToOmit);
      assertThrows(
          "Expected failure when omitting " + fieldToOmit,
          IllegalArgumentException.class,
          () -> EncryptedValue.fromJsonObject(json));
    }
  }

  @Test
  public void testFromJsonObject_nonPrimitiveFields() {
    List<String> fields = List.of("version", "algorithm", "iv", "ciphertext", "signature");
    for (String field : fields) {
      JsonObject jsonWithObject = createValidJsonObject();
      jsonWithObject.add(field, new JsonObject());
      assertThrows(
          "Expected failure when " + field + " is JsonObject",
          IllegalArgumentException.class,
          () -> EncryptedValue.fromJsonObject(jsonWithObject));

      JsonObject jsonWithArray = createValidJsonObject();
      jsonWithArray.add(field, new JsonArray());
      assertThrows(
          "Expected failure when " + field + " is JsonArray",
          IllegalArgumentException.class,
          () -> EncryptedValue.fromJsonObject(jsonWithArray));

      JsonObject jsonWithNull = createValidJsonObject();
      jsonWithNull.add(field, JsonNull.INSTANCE);
      assertThrows(
          "Expected failure when " + field + " is JsonNull",
          IllegalArgumentException.class,
          () -> EncryptedValue.fromJsonObject(jsonWithNull));
    }
  }

  @Test
  public void testFromJsonObject_unknownOrInvalidVersion() {
    JsonObject jsonVersion1 = createValidJsonObject();
    jsonVersion1.addProperty("version", 1);
    assertThrows(IllegalArgumentException.class, () -> EncryptedValue.fromJsonObject(jsonVersion1));

    JsonObject jsonVersionNegative = createValidJsonObject();
    jsonVersionNegative.addProperty("version", -1);
    assertThrows(IllegalArgumentException.class, () -> EncryptedValue.fromJsonObject(jsonVersionNegative));

    JsonObject jsonVersionString = createValidJsonObject();
    jsonVersionString.addProperty("version", "not-a-number");
    assertThrows(IllegalArgumentException.class, () -> EncryptedValue.fromJsonObject(jsonVersionString));
  }

  @Test
  public void testFromJsonObject_unknownAlgorithm() {
    JsonObject json = createValidJsonObject();
    json.addProperty("algorithm", "DES_EDE3_CBC");
    assertThrows(IllegalArgumentException.class, () -> EncryptedValue.fromJsonObject(json));
  }

  @Test
  public void testFromJsonObject_invalidBase64() {
    JsonObject invalidIv = createValidJsonObject();
    invalidIv.addProperty("iv", "not base 64!!!");
    assertThrows(IllegalArgumentException.class, () -> EncryptedValue.fromJsonObject(invalidIv));

    JsonObject invalidCiphertext = createValidJsonObject();
    invalidCiphertext.addProperty("ciphertext", "%%%badbase64");
    assertThrows(IllegalArgumentException.class, () -> EncryptedValue.fromJsonObject(invalidCiphertext));

    JsonObject invalidSignature = createValidJsonObject();
    invalidSignature.addProperty("signature", "&&&badsignature");
    assertThrows(IllegalArgumentException.class, () -> EncryptedValue.fromJsonObject(invalidSignature));
  }

  @Test
  public void testFromJsonObject_wrongDecodedLengths() {
    // IV wrong length (15 bytes)
    JsonObject badIv = createValidJsonObject();
    badIv.addProperty("iv", BaseEncoding.base64().encode(new byte[15]));
    assertThrows(IllegalArgumentException.class, () -> EncryptedValue.fromJsonObject(badIv));

    // Ciphertext empty (0 bytes)
    JsonObject emptyCipher = createValidJsonObject();
    emptyCipher.addProperty("ciphertext", BaseEncoding.base64().encode(new byte[0]));
    assertThrows(IllegalArgumentException.class, () -> EncryptedValue.fromJsonObject(emptyCipher));

    // Ciphertext too large (> 64 KiB)
    JsonObject hugeCipher = createValidJsonObject();
    hugeCipher.addProperty("ciphertext", BaseEncoding.base64().encode(new byte[EncryptedValue.MAX_CIPHERTEXT_BYTES + 1]));
    assertThrows(IllegalArgumentException.class, () -> EncryptedValue.fromJsonObject(hugeCipher));

    // Signature wrong length (31 bytes)
    JsonObject badSig = createValidJsonObject();
    badSig.addProperty("signature", BaseEncoding.base64().encode(new byte[31]));
    assertThrows(IllegalArgumentException.class, () -> EncryptedValue.fromJsonObject(badSig));
  }

  @Test
  public void testFromJsonArray_validSingle() {
    JsonArray array = new JsonArray();
    array.add(createValidJsonObject());
    List<EncryptedValue> list = EncryptedValue.fromJsonArray(array);
    assertThat(list).hasSize(1);
    assertThat(list.get(0).getAlgorithm()).isEqualTo(ALGORITHM);
  }

  @Test
  public void testFromJsonArray_validMaxElements() {
    JsonArray array = new JsonArray();
    for (int i = 0; i < EncryptedValue.MAX_ENCRYPTIONS; i++) {
      array.add(createValidJsonObject());
    }
    List<EncryptedValue> list = EncryptedValue.fromJsonArray(array);
    assertThat(list).hasSize(EncryptedValue.MAX_ENCRYPTIONS);
  }

  @Test
  public void testFromJsonArray_nullArray() {
    assertThrows(IllegalArgumentException.class, () -> EncryptedValue.fromJsonArray(null));
  }

  @Test
  public void testFromJsonArray_emptyArray() {
    JsonArray empty = new JsonArray();
    assertThrows(IllegalArgumentException.class, () -> EncryptedValue.fromJsonArray(empty));
  }

  @Test
  public void testFromJsonArray_tooManyElements() {
    JsonArray array = new JsonArray();
    for (int i = 0; i < EncryptedValue.MAX_ENCRYPTIONS + 1; i++) {
      array.add(createValidJsonObject());
    }
    assertThrows(IllegalArgumentException.class, () -> EncryptedValue.fromJsonArray(array));
  }

  @Test
  public void testFromJsonArray_invalidElements() {
    JsonArray arrayWithPrimitive = new JsonArray();
    arrayWithPrimitive.add(new JsonPrimitive("not an object"));
    assertThrows(IllegalArgumentException.class, () -> EncryptedValue.fromJsonArray(arrayWithPrimitive));

    JsonArray arrayWithNull = new JsonArray();
    arrayWithNull.add(JsonNull.INSTANCE);
    assertThrows(IllegalArgumentException.class, () -> EncryptedValue.fromJsonArray(arrayWithNull));

    JsonArray arrayWithNestedArray = new JsonArray();
    arrayWithNestedArray.add(new JsonArray());
    assertThrows(IllegalArgumentException.class, () -> EncryptedValue.fromJsonArray(arrayWithNestedArray));

    JsonArray arrayWithInvalidEncryptedValue = new JsonArray();
    JsonObject badObj = createValidJsonObject();
    badObj.remove("algorithm");
    arrayWithInvalidEncryptedValue.add(badObj);
    assertThrows(IllegalArgumentException.class, () -> EncryptedValue.fromJsonArray(arrayWithInvalidEncryptedValue));
  }

  @Test
  public void testTextRoundTrip() {
    EncryptedValue original = new EncryptedValue(ALGORITHM, VALID_IV, VALID_CIPHERTEXT, VALID_SIGNATURE);
    Text text = original.toText();

    EncryptedValue restored = EncryptedValue.fromText(text);
    assertThat(restored.getAlgorithm()).isEqualTo(original.getAlgorithm());
    assertThat(restored.getIv()).isEqualTo(original.getIv());
    assertThat(restored.getCiphertext()).isEqualTo(original.getCiphertext());
    assertThat(restored.getSignature()).isEqualTo(original.getSignature());
  }

  @Test
  public void testFromText_invalidFormats() {
    assertThrows(IllegalArgumentException.class, () -> EncryptedValue.fromText(null));
    assertThrows(IllegalArgumentException.class, () -> EncryptedValue.fromText(new Text("")));
    assertThrows(IllegalArgumentException.class, () -> EncryptedValue.fromText(new Text("0:AES_256_CBC_HMAC_SHA256:iv:cipher")));
    assertThrows(IllegalArgumentException.class, () -> EncryptedValue.fromText(new Text("1:AES_256_CBC_HMAC_SHA256:a:b:c")));
    assertThrows(IllegalArgumentException.class, () -> EncryptedValue.fromText(new Text("0:UNKNOWN_ALGO:a:b:c")));
  }

  @Test
  public void testTextListRoundTrip() {
    EncryptedValue ev1 = new EncryptedValue(ALGORITHM, VALID_IV, "val1".getBytes(StandardCharsets.UTF_8), VALID_SIGNATURE);
    EncryptedValue ev2 = new EncryptedValue(ALGORITHM, VALID_IV, "val2".getBytes(StandardCharsets.UTF_8), VALID_SIGNATURE);
    List<EncryptedValue> originalList = List.of(ev1, ev2);

    List<Text> textList = EncryptedValue.toTextList(originalList);
    assertThat(textList).hasSize(2);

    List<EncryptedValue> restoredList = EncryptedValue.fromTextList(textList);
    assertThat(restoredList).hasSize(2);
    assertThat(restoredList.get(0).getCiphertext()).isEqualTo("val1".getBytes(StandardCharsets.UTF_8));
    assertThat(restoredList.get(1).getCiphertext()).isEqualTo("val2".getBytes(StandardCharsets.UTF_8));
  }

  private static JsonObject createValidJsonObject() {
    EncryptedValue ev = new EncryptedValue(ALGORITHM, VALID_IV, VALID_CIPHERTEXT, VALID_SIGNATURE);
    return ev.toJsonObject();
  }
}
