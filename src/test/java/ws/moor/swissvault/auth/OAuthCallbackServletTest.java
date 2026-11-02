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
import com.google.gson.JsonParser;
import org.junit.Before;
import org.junit.Test;
import ws.moor.swissvault.util.UriBuilder;

import javax.crypto.spec.SecretKeySpec;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.lang.reflect.Proxy;
import java.net.http.HttpClient;
import java.time.Clock;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;

import static com.google.common.truth.Truth.assertThat;

public class OAuthCallbackServletTest {

  private static final SecretKeySpec HMAC_KEY = new SecretKeySpec(new byte[32], "HmacSHA256");

  private UriBuilder uriBuilder;
  private OAuthStateHelper stateHelper;
  private AuthCookieFactory cookieFactory;
  private FakeAuthHelper authHelper;
  private OAuthCallbackServlet servlet;

  @Before
  public void setUp() {
    uriBuilder = new UriBuilder("http", "localhost:8080");
    stateHelper = new OAuthStateHelper(false);
    cookieFactory = new AuthCookieFactory(false, HMAC_KEY, Clock.systemUTC());
    authHelper = new FakeAuthHelper(uriBuilder);
    servlet = new OAuthCallbackServlet(authHelper, stateHelper, cookieFactory, uriBuilder);
  }

  @Test
  public void testMissingStateParameterReturns400() throws Exception {
    FakeResponse resp = new FakeResponse();
    HttpServletRequest req = createFakeRequest(
        Map.of("code", "valid_code"),
        new Cookie[]{new Cookie("oauth_state", "HOME:1234567890abcdef1234567890abcdef")});

    servlet.doGet(req, resp.asHttpServletResponse());

    assertThat(resp.errorCode).isEqualTo(HttpServletResponse.SC_BAD_REQUEST);
    assertThat(resp.redirectLocation).isNull();
    assertThat(authHelper.determineUserIdCalled.get()).isFalse();
    assertThat(resp.headers.get(HttpHeaders.SET_COOKIE)).contains("oauth_state=; Max-Age=0; Path=/; HttpOnly; SameSite=Lax");
  }

  @Test
  public void testMissingCookieReturns400() throws Exception {
    FakeResponse resp = new FakeResponse();
    HttpServletRequest req = createFakeRequest(
        Map.of("code", "valid_code", "state", "HOME:1234567890abcdef1234567890abcdef"),
        null);

    servlet.doGet(req, resp.asHttpServletResponse());

    assertThat(resp.errorCode).isEqualTo(HttpServletResponse.SC_BAD_REQUEST);
    assertThat(resp.redirectLocation).isNull();
    assertThat(authHelper.determineUserIdCalled.get()).isFalse();
  }

  @Test
  public void testMismatchedStateReturns400() throws Exception {
    FakeResponse resp = new FakeResponse();
    HttpServletRequest req = createFakeRequest(
        Map.of("code", "valid_code", "state", "HOME:1234567890abcdef1234567890abcdef"),
        new Cookie[]{new Cookie("oauth_state", "HOME:othernonce1234567890abcdef")});

    servlet.doGet(req, resp.asHttpServletResponse());

    assertThat(resp.errorCode).isEqualTo(HttpServletResponse.SC_BAD_REQUEST);
    assertThat(resp.redirectLocation).isNull();
    assertThat(authHelper.determineUserIdCalled.get()).isFalse();
  }

  @Test
  public void testLegacyStaticStateReturns400() throws Exception {
    // Attack scenario: /oauth2callback?code=attacker_code&state=HOME
    FakeResponse resp = new FakeResponse();
    HttpServletRequest req = createFakeRequest(
        Map.of("code", "attacker_code", "state", "HOME"),
        new Cookie[]{new Cookie("oauth_state", "HOME")});

    servlet.doGet(req, resp.asHttpServletResponse());

    assertThat(resp.errorCode).isEqualTo(HttpServletResponse.SC_BAD_REQUEST);
    assertThat(resp.redirectLocation).isNull();
    assertThat(authHelper.determineUserIdCalled.get()).isFalse();
  }

  @Test
  public void testMissingCodeReturns400() throws Exception {
    String state = stateHelper.createStateValue(OAuthState.HOME);
    FakeResponse resp = new FakeResponse();
    HttpServletRequest req = createFakeRequest(
        Map.of("state", state),
        new Cookie[]{new Cookie("oauth_state", state)});

    servlet.doGet(req, resp.asHttpServletResponse());

    assertThat(resp.errorCode).isEqualTo(HttpServletResponse.SC_BAD_REQUEST);
    assertThat(resp.redirectLocation).isNull();
    assertThat(authHelper.determineUserIdCalled.get()).isFalse();
  }

  @Test
  public void testSuccessfulCallbackForHome() throws Exception {
    String state = stateHelper.createStateValue(OAuthState.HOME);
    FakeResponse resp = new FakeResponse();
    HttpServletRequest req = createFakeRequest(
        Map.of("code", "valid_code", "state", state),
        new Cookie[]{new Cookie("oauth_state", state)});

    servlet.doGet(req, resp.asHttpServletResponse());

    assertThat(resp.errorCode).isNull();
    assertThat(resp.redirectLocation).isEqualTo("http://localhost:8080/");
    assertThat(authHelper.determineUserIdCalled.get()).isTrue();

    // Verify cookies: state cookie cleared, auth cookie set
    List<String> setCookies = resp.headers.get(HttpHeaders.SET_COOKIE);
    assertThat(setCookies).hasSize(2);
    assertThat(setCookies.get(0)).isEqualTo("oauth_state=; Max-Age=0; Path=/; HttpOnly; SameSite=Lax");
    assertThat(setCookies.get(1)).startsWith("auth=user-123:");
  }

  @Test
  public void testSuccessfulCallbackForCliLogin() throws Exception {
    String state = stateHelper.createStateValue(OAuthState.CLI_LOGIN);
    FakeResponse resp = new FakeResponse();
    HttpServletRequest req = createFakeRequest(
        Map.of("code", "valid_code", "state", state),
        new Cookie[]{new Cookie("oauth_state", state)});

    servlet.doGet(req, resp.asHttpServletResponse());

    assertThat(resp.errorCode).isNull();
    assertThat(resp.redirectLocation).isEqualTo("http://localhost:8080/cli-login");
    assertThat(authHelper.determineUserIdCalled.get()).isTrue();

    List<String> setCookies = resp.headers.get(HttpHeaders.SET_COOKIE);
    assertThat(setCookies).hasSize(2);
    assertThat(setCookies.get(0)).isEqualTo("oauth_state=; Max-Age=0; Path=/; HttpOnly; SameSite=Lax");
    assertThat(setCookies.get(1)).startsWith("auth=user-123:");
  }

  private static class FakeAuthHelper extends AuthHelper {
    final AtomicBoolean determineUserIdCalled = new AtomicBoolean(false);

    FakeAuthHelper(UriBuilder uriBuilder) {
      super(HttpClient.newHttpClient(), new JsonParser(), uriBuilder, "secret", "client-id");
    }

    @Override
    public UserId determineUserId(String code) throws IOException {
      determineUserIdCalled.set(true);
      if ("valid_code".equals(code)) {
        return UserId.fromString("user-123");
      }
      throw new IOException("invalid code");
    }
  }

  private static class FakeResponse {
    Integer errorCode;
    String errorMessage;
    String redirectLocation;
    final Map<String, List<String>> headers = new HashMap<>();

    HttpServletResponse asHttpServletResponse() {
      return (HttpServletResponse) Proxy.newProxyInstance(
          HttpServletResponse.class.getClassLoader(),
          new Class<?>[]{HttpServletResponse.class},
          (proxy, method, args) -> {
            String name = method.getName();
            if ("sendError".equals(name)) {
              errorCode = (Integer) args[0];
              if (args.length > 1) {
                errorMessage = (String) args[1];
              }
              return null;
            } else if ("sendRedirect".equals(name)) {
              redirectLocation = (String) args[0];
              return null;
            } else if ("addHeader".equals(name)) {
              headers.computeIfAbsent((String) args[0], k -> new ArrayList<>()).add((String) args[1]);
              return null;
            }
            return null;
          });
    }
  }

  private static HttpServletRequest createFakeRequest(Map<String, String> params, Cookie[] cookies) {
    Map<String, String> nonNullParams = params != null ? params : new HashMap<>();
    return (HttpServletRequest) Proxy.newProxyInstance(
        HttpServletRequest.class.getClassLoader(),
        new Class<?>[]{HttpServletRequest.class},
        (proxy, method, args) -> {
          if ("getParameter".equals(method.getName())) {
            return nonNullParams.get(args[0]);
          } else if ("getCookies".equals(method.getName())) {
            return cookies;
          }
          return null;
        });
  }

  private void doGet(HttpServletRequest req, FakeResponse resp) throws IOException {
    servlet.doGet(req, resp.asHttpServletResponse());
  }
}
