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
package ws.moor.swissvault.auth;

import com.google.common.net.HttpHeaders;
import org.junit.Before;
import org.junit.Test;

import javax.crypto.spec.SecretKeySpec;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.lang.reflect.Proxy;
import java.time.Clock;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static com.google.common.truth.Truth.assertThat;

public class LogoutServletTest {

  private static final SecretKeySpec HMAC_KEY = new SecretKeySpec(new byte[32], "HmacSHA256");

  private AuthCookieFactory insecureFactory;
  private AuthCookieFactory secureFactory;

  @Before
  public void setUp() {
    insecureFactory = new AuthCookieFactory(false, HMAC_KEY, Clock.systemUTC());
    secureFactory = new AuthCookieFactory(true, HMAC_KEY, Clock.systemUTC());
  }

  @Test
  public void testLogoutClearsCookieAndRendersLoggedOutPage() throws IOException {
    LogoutServlet servlet = new LogoutServlet(insecureFactory);
    FakeResponse resp = new FakeResponse();
    HttpServletRequest req = createFakeRequest();

    servlet.doGet(req, resp.asHttpServletResponse());

    List<String> setCookies = resp.headers.get(HttpHeaders.SET_COOKIE);
    assertThat(setCookies).containsExactly("auth=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax");
    assertThat(resp.contentType).isEqualTo("text/html; charset=UTF-8");

    String html = resp.getOutput();
    assertThat(html).contains("<title>Swiss Vault - Logged Out</title>");
    assertThat(html).contains("<h2>Logged Out</h2>");
    assertThat(html).contains("<p>You have been logged out of Swiss Vault.</p>");
    assertThat(html).contains("<p><a href=\"/\">Log in again</a></p>");
  }

  @Test
  public void testLogoutWithSecureOnlySetsSecureFlag() throws IOException {
    LogoutServlet servlet = new LogoutServlet(secureFactory);
    FakeResponse resp = new FakeResponse();
    HttpServletRequest req = createFakeRequest();

    servlet.doGet(req, resp.asHttpServletResponse());

    List<String> setCookies = resp.headers.get(HttpHeaders.SET_COOKIE);
    assertThat(setCookies).containsExactly("auth=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax; Secure");
    assertThat(resp.contentType).isEqualTo("text/html; charset=UTF-8");

    String html = resp.getOutput();
    assertThat(html).contains("<a href=\"/\">Log in again</a>");
  }

  private static HttpServletRequest createFakeRequest() {
    return (HttpServletRequest) Proxy.newProxyInstance(
        HttpServletRequest.class.getClassLoader(),
        new Class<?>[]{HttpServletRequest.class},
        (proxy, method, args) -> null);
  }

  private static class FakeResponse {
    String contentType;
    final Map<String, List<String>> headers = new HashMap<>();
    final StringWriter stringWriter = new StringWriter();
    final PrintWriter printWriter = new PrintWriter(stringWriter);

    HttpServletResponse asHttpServletResponse() {
      return (HttpServletResponse) Proxy.newProxyInstance(
          HttpServletResponse.class.getClassLoader(),
          new Class<?>[]{HttpServletResponse.class},
          (proxy, method, args) -> {
            String name = method.getName();
            if ("addHeader".equals(name)) {
              headers.computeIfAbsent((String) args[0], k -> new ArrayList<>()).add((String) args[1]);
              return null;
            } else if ("setContentType".equals(name)) {
              contentType = (String) args[0];
              return null;
            } else if ("getWriter".equals(name)) {
              return printWriter;
            }
            return null;
          });
    }

    String getOutput() {
      printWriter.flush();
      return stringWriter.toString();
    }
  }
}
