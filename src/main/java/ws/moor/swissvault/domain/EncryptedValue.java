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
package ws.moor.swissvault.domain;


import com.google.appengine.api.datastore.Text;
import com.google.common.collect.Lists;
import com.google.common.io.BaseEncoding;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import java.util.List;

import static com.google.common.base.Preconditions.checkArgument;

public class EncryptedValue {

  public static final int MAX_CIPHERTEXT_BYTES = 64 * 1024;
  public static final int MAX_ENCRYPTIONS = 16;

  private final EncryptionAlgorithm algorithm;
  private final byte[] iv;
  private final byte[] ciphertext;
  private final byte[] signature;

  public EncryptedValue(EncryptionAlgorithm algorithm, byte[] iv, byte[] ciphertext, byte[] signature) {
    checkArgument(algorithm != null, "algorithm cannot be null");
    checkArgument(
        iv != null && iv.length == algorithm.getIvLengthBytes(),
        "invalid iv length: %s",
        iv == null ? "null" : iv.length);
    checkArgument(
        ciphertext != null && ciphertext.length >= algorithm.getMinCiphertextLengthBytes() && ciphertext.length <= MAX_CIPHERTEXT_BYTES,
        "invalid ciphertext length: %s",
        ciphertext == null ? "null" : ciphertext.length);
    checkArgument(
        signature != null && signature.length == algorithm.getSignatureLengthBytes(),
        "invalid signature length: %s",
        signature == null ? "null" : signature.length);
    this.algorithm = algorithm;
    this.iv = iv;
    this.ciphertext = ciphertext;
    this.signature = signature;
  }

  public EncryptionAlgorithm getAlgorithm() {
    return algorithm;
  }

  public byte[] getIv() {
    return iv.clone();
  }

  public byte[] getCiphertext() {
    return ciphertext.clone();
  }

  public byte[] getSignature() {
    return signature.clone();
  }

  public static EncryptedValue fromText(Text text) {
    checkArgument(text != null, "text cannot be null");
    String[] parts = text.getValue().split(":", -1);
    if (parts.length != 5) {
      throw new IllegalArgumentException(text.getValue());
    }
    if (!parts[0].equals("0")) {
      throw new IllegalArgumentException(text.getValue());
    }
    EncryptionAlgorithm algorithm;
    try {
      algorithm = EncryptionAlgorithm.valueOf(parts[1]);
    } catch (IllegalArgumentException e) {
      throw new IllegalArgumentException("unknown algorithm: " + parts[1], e);
    }

    byte[] iv = BaseEncoding.base64().decode(parts[2]);
    byte[] ciphertext = BaseEncoding.base64().decode(parts[3]);
    byte[] signature = BaseEncoding.base64().decode(parts[4]);
    return new EncryptedValue(algorithm, iv, ciphertext, signature);
  }

  public Text toText() {
    StringBuilder encoded = new StringBuilder();
    encoded.append("0:");
    encoded.append(algorithm.name()).append(":");
    encoded.append(BaseEncoding.base64().encode(iv)).append(":");
    encoded.append(BaseEncoding.base64().encode(ciphertext)).append(":");
    encoded.append(BaseEncoding.base64().encode(signature));
    return new Text(encoded.toString());
  }

  public JsonObject toJsonObject() {
    JsonObject object = new JsonObject();
    object.addProperty("version", 0);
    object.addProperty("algorithm", algorithm.name());
    object.addProperty("iv", BaseEncoding.base64().encode(iv));
    object.addProperty("ciphertext", BaseEncoding.base64().encode(ciphertext));
    object.addProperty("signature", BaseEncoding.base64().encode(signature));
    return object;
  }

  public static EncryptedValue fromJsonObject(JsonObject json) {
    checkArgument(json != null, "missing encrypted value");
    checkPrimitiveField(json, "version");
    checkPrimitiveField(json, "algorithm");
    checkPrimitiveField(json, "iv");
    checkPrimitiveField(json, "ciphertext");
    checkPrimitiveField(json, "signature");

    int version;
    try {
      version = json.getAsJsonPrimitive("version").getAsInt();
    } catch (ClassCastException | NumberFormatException | UnsupportedOperationException e) {
      throw new IllegalArgumentException("invalid version format", e);
    }
    if (version != 0) {
      throw new IllegalArgumentException("unknown version: " + version);
    }

    String algorithmName = json.getAsJsonPrimitive("algorithm").getAsString();
    EncryptionAlgorithm algorithm;
    try {
      algorithm = EncryptionAlgorithm.valueOf(algorithmName);
    } catch (IllegalArgumentException e) {
      throw new IllegalArgumentException("unknown algorithm: " + algorithmName, e);
    }

    byte[] iv;
    byte[] ciphertext;
    byte[] signature;
    try {
      iv = BaseEncoding.base64().decode(json.getAsJsonPrimitive("iv").getAsString());
      ciphertext = BaseEncoding.base64().decode(json.getAsJsonPrimitive("ciphertext").getAsString());
      signature = BaseEncoding.base64().decode(json.getAsJsonPrimitive("signature").getAsString());
    } catch (IllegalArgumentException e) {
      throw new IllegalArgumentException("invalid base64 encoding", e);
    }

    return new EncryptedValue(algorithm, iv, ciphertext, signature);
  }

  private static void checkPrimitiveField(JsonObject json, String fieldName) {
    checkArgument(
        json.has(fieldName) && json.get(fieldName) != null && json.get(fieldName).isJsonPrimitive(),
        "missing or invalid field: %s",
        fieldName);
  }

  public static List<Text> toTextList(List<EncryptedValue> values) {
    checkArgument(values != null, "missing values list");
    List<Text> result = Lists.newArrayListWithCapacity(values.size());
    for (EncryptedValue value : values) {
      checkArgument(value != null, "null value in list");
      result.add(value.toText());
    }
    return result;
  }

  public static List<EncryptedValue> fromTextList(List<Text> texts) {
    checkArgument(texts != null, "missing texts list");
    List<EncryptedValue> result = Lists.newArrayListWithCapacity(texts.size());
    for (Text text : texts) {
      checkArgument(text != null, "null text in list");
      result.add(fromText(text));
    }
    return result;
  }

  public static List<EncryptedValue> fromJsonArray(JsonArray encryptions) {
    checkArgument(encryptions != null, "missing encryptions array");
    checkArgument(
        encryptions.size() >= 1 && encryptions.size() <= MAX_ENCRYPTIONS,
        "invalid encryptions count: %s",
        encryptions.size());
    List<EncryptedValue> list = Lists.newArrayListWithCapacity(encryptions.size());
    for (int i = 0; i < encryptions.size(); i++) {
      JsonElement element = encryptions.get(i);
      checkArgument(element != null && element.isJsonObject(), "invalid encryption entry");
      list.add(fromJsonObject(element.getAsJsonObject()));
    }
    return list;
  }
}
