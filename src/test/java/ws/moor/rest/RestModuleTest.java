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
package ws.moor.rest;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.junit.Test;

import javax.servlet.ReadListener;
import javax.servlet.ServletInputStream;
import javax.servlet.http.HttpServletRequest;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertThrows;

public class RestModuleTest {

  private final RestModule restModule = new RestModule();
  private final JsonParser jsonParser = new JsonParser();

  @Test
  public void testProvideRequestBody_emptyBody() throws Exception {
    HttpServletRequest request = createRequestWithBody(new byte[0]);
    String result = restModule.provideRequestBody(request);
    assertThat(result).isEmpty();
  }

  @Test
  public void testProvideRequestBody_normalBody() throws Exception {
    String content = "{\"hello\":\"world\"}";
    HttpServletRequest request = createRequestWithBody(content.getBytes(StandardCharsets.UTF_8));
    String result = restModule.provideRequestBody(request);
    assertThat(result).isEqualTo(content);
  }

  @Test
  public void testProvideRequestBody_utf8MultiByteCharacters() throws Exception {
    String unicodeContent = "{\n  \"message\": \"Hello, 世界! 🔐 \uD83D\uDE00 𝄞 — café\"\n}";
    byte[] utf8Bytes = unicodeContent.getBytes(StandardCharsets.UTF_8);
    HttpServletRequest request = createRequestWithBody(utf8Bytes);
    String result = restModule.provideRequestBody(request);
    assertThat(result).isEqualTo(unicodeContent);
  }

  @Test
  public void testProvideRequestBody_exactlyMaxBytes() throws Exception {
    byte[] exactMaxBytes = new byte[RestModule.MAX_REQUEST_BODY_BYTES];
    Arrays.fill(exactMaxBytes, (byte) 'A');
    HttpServletRequest request = createRequestWithBody(exactMaxBytes);
    String result = restModule.provideRequestBody(request);
    assertThat(result).hasLength(RestModule.MAX_REQUEST_BODY_BYTES);
    assertThat(result).isEqualTo(new String(exactMaxBytes, StandardCharsets.UTF_8));
  }

  @Test
  public void testProvideRequestBody_exceedsMaxBytesByOne() {
    byte[] tooLargeBytes = new byte[RestModule.MAX_REQUEST_BODY_BYTES + 1];
    Arrays.fill(tooLargeBytes, (byte) 'B');
    HttpServletRequest request = createRequestWithBody(tooLargeBytes);

    IllegalArgumentException thrown = assertThrows(
        IllegalArgumentException.class,
        () -> restModule.provideRequestBody(request));
    assertThat(thrown).hasMessageThat().contains("exceeds maximum size");
    assertThat(thrown).hasMessageThat().contains(String.valueOf(RestModule.MAX_REQUEST_BODY_BYTES));
  }

  @Test
  public void testProvideRequestBody_muchLargerThanMaxBytes() {
    byte[] largeBytes = new byte[RestModule.MAX_REQUEST_BODY_BYTES * 2];
    Arrays.fill(largeBytes, (byte) 'C');
    HttpServletRequest request = createRequestWithBody(largeBytes);

    IllegalArgumentException thrown = assertThrows(
        IllegalArgumentException.class,
        () -> restModule.provideRequestBody(request));
    assertThat(thrown).hasMessageThat().contains("exceeds maximum size");
  }

  @Test
  public void testProvideRequestArray_validArray() {
    String body = "[{\"id\":1},{\"id\":2}]";
    JsonArray array = restModule.provideRequestArray(jsonParser, body);
    assertThat(array).isNotNull();
    assertThat(array.size()).isEqualTo(2);
    assertThat(array.get(0).getAsJsonObject().get("id").getAsInt()).isEqualTo(1);
    assertThat(array.get(1).getAsJsonObject().get("id").getAsInt()).isEqualTo(2);
  }

  @Test
  public void testProvideRequestArray_emptyArray() {
    String body = "[]";
    JsonArray array = restModule.provideRequestArray(jsonParser, body);
    assertThat(array).isNotNull();
    assertThat(array.size()).isEqualTo(0);
  }

  @Test
  public void testProvideRequestArray_nullBody() {
    assertThrows(IllegalArgumentException.class, () -> restModule.provideRequestArray(jsonParser, null));
  }

  @Test
  public void testProvideRequestArray_emptyString() {
    assertThrows(IllegalArgumentException.class, () -> restModule.provideRequestArray(jsonParser, ""));
  }

  @Test
  public void testProvideRequestArray_malformedJson() {
    assertThrows(IllegalArgumentException.class, () -> restModule.provideRequestArray(jsonParser, "[invalid json"));
  }

  @Test
  public void testProvideRequestArray_objectInsteadOfArray() {
    assertThrows(IllegalArgumentException.class, () -> restModule.provideRequestArray(jsonParser, "{\"key\":\"val\"}"));
  }

  @Test
  public void testProvideRequestArray_primitiveInsteadOfArray() {
    assertThrows(IllegalArgumentException.class, () -> restModule.provideRequestArray(jsonParser, "\"hello\""));
    assertThrows(IllegalArgumentException.class, () -> restModule.provideRequestArray(jsonParser, "123"));
    assertThrows(IllegalArgumentException.class, () -> restModule.provideRequestArray(jsonParser, "true"));
    assertThrows(IllegalArgumentException.class, () -> restModule.provideRequestArray(jsonParser, "null"));
  }

  @Test
  public void testProvideRequestObject_validObject() {
    String body = "{\"name\":\"Alice\",\"active\":true}";
    JsonObject object = restModule.provideRequestObject(jsonParser, body);
    assertThat(object).isNotNull();
    assertThat(object.get("name").getAsString()).isEqualTo("Alice");
    assertThat(object.get("active").getAsBoolean()).isTrue();
  }

  @Test
  public void testProvideRequestObject_emptyObject() {
    String body = "{}";
    JsonObject object = restModule.provideRequestObject(jsonParser, body);
    assertThat(object).isNotNull();
    assertThat(object.keySet()).isEmpty();
  }

  @Test
  public void testProvideRequestObject_nullBody() {
    assertThrows(IllegalArgumentException.class, () -> restModule.provideRequestObject(jsonParser, null));
  }

  @Test
  public void testProvideRequestObject_emptyString() {
    assertThrows(IllegalArgumentException.class, () -> restModule.provideRequestObject(jsonParser, ""));
  }

  @Test
  public void testProvideRequestObject_malformedJson() {
    assertThrows(IllegalArgumentException.class, () -> restModule.provideRequestObject(jsonParser, "{unclosed"));
  }

  @Test
  public void testProvideRequestObject_arrayInsteadOfObject() {
    assertThrows(IllegalArgumentException.class, () -> restModule.provideRequestObject(jsonParser, "[1, 2, 3]"));
  }

  @Test
  public void testProvideRequestObject_primitiveInsteadOfObject() {
    assertThrows(IllegalArgumentException.class, () -> restModule.provideRequestObject(jsonParser, "\"hello\""));
    assertThrows(IllegalArgumentException.class, () -> restModule.provideRequestObject(jsonParser, "42"));
    assertThrows(IllegalArgumentException.class, () -> restModule.provideRequestObject(jsonParser, "false"));
    assertThrows(IllegalArgumentException.class, () -> restModule.provideRequestObject(jsonParser, "null"));
  }

  private static HttpServletRequest createRequestWithBody(byte[] body) {
    return (HttpServletRequest) Proxy.newProxyInstance(
        HttpServletRequest.class.getClassLoader(),
        new Class<?>[]{HttpServletRequest.class},
        (proxy, method, args) -> {
          if ("getInputStream".equals(method.getName())) {
            return new DelegatingServletInputStream(body);
          }
          return null;
        });
  }

  private static class DelegatingServletInputStream extends ServletInputStream {
    private final ByteArrayInputStream inputStream;

    DelegatingServletInputStream(byte[] data) {
      this.inputStream = new ByteArrayInputStream(data);
    }

    @Override
    public int read() {
      return inputStream.read();
    }

    @Override
    public int read(byte[] b, int off, int len) {
      return inputStream.read(b, off, len);
    }

    @Override
    public boolean isFinished() {
      return inputStream.available() == 0;
    }

    @Override
    public boolean isReady() {
      return true;
    }

    @Override
    public void setReadListener(ReadListener readListener) {
      throw new UnsupportedOperationException();
    }
  }
}
