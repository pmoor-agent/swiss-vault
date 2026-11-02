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

import com.google.common.base.Optional;
import org.junit.Test;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import java.lang.reflect.Proxy;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;

import static com.google.common.truth.Truth.assertThat;

public class OAuthStateHelperTest {

  private final OAuthStateHelper helperInsecure = new OAuthStateHelper(false, new SecureRandom());
  private final OAuthStateHelper helperSecure = new OAuthStateHelper(true, new SecureRandom());

  @Test
  public void testCreateStateValue() {
    String stateHome = helperInsecure.createStateValue(OAuthState.HOME);
    assertThat(stateHome).startsWith("HOME:");
    String[] partsHome = stateHome.split(":");
    assertThat(partsHome).hasLength(2);
    assertThat(partsHome[1]).matches("^[0-9a-f]{64}$");

    String stateCli = helperInsecure.createStateValue(OAuthState.CLI_LOGIN);
    assertThat(stateCli).startsWith("CLI_LOGIN:");
    String[] partsCli = stateCli.split(":");
    assertThat(partsCli).hasLength(2);
    assertThat(partsCli[1]).matches("^[0-9a-f]{64}$");

    // Random nonces must differ across calls
    String anotherHome = helperInsecure.createStateValue(OAuthState.HOME);
    assertThat(anotherHome).isNotEqualTo(stateHome);
  }

  @Test
  public void testCreateCookieHeader() {
    String cookieHeader = helperInsecure.createCookieHeader("HOME:1234567890abcdef1234567890abcdef");
    assertThat(cookieHeader).isEqualTo(
        "oauth_state=HOME:1234567890abcdef1234567890abcdef; Max-Age=600; Path=/; HttpOnly; SameSite=Lax");

    String secureCookieHeader = helperSecure.createCookieHeader("HOME:1234567890abcdef1234567890abcdef");
    assertThat(secureCookieHeader).isEqualTo(
        "oauth_state=HOME:1234567890abcdef1234567890abcdef; Max-Age=600; Path=/; HttpOnly; SameSite=Lax; Secure");
  }

  @Test
  public void testCreateClearCookieHeader() {
    String clearHeader = helperInsecure.createClearCookieHeader();
    assertThat(clearHeader).isEqualTo("oauth_state=; Max-Age=0; Path=/; HttpOnly; SameSite=Lax");

    String secureClearHeader = helperSecure.createClearCookieHeader();
    assertThat(secureClearHeader).isEqualTo("oauth_state=; Max-Age=0; Path=/; HttpOnly; SameSite=Lax; Secure");
  }

  @Test
  public void testValidateSuccess() {
    String stateHome = helperInsecure.createStateValue(OAuthState.HOME);
    HttpServletRequest reqHome = createFakeRequest(
        Map.of("state", stateHome),
        new Cookie[]{new Cookie("oauth_state", stateHome)});

    Optional<OAuthState> extractedHome = helperInsecure.validateAndExtractState(reqHome);
    assertThat(extractedHome.isPresent()).isTrue();
    assertThat(extractedHome.get()).isEqualTo(OAuthState.HOME);

    String stateCli = helperInsecure.createStateValue(OAuthState.CLI_LOGIN);
    HttpServletRequest reqCli = createFakeRequest(
        Map.of("state", stateCli),
        new Cookie[]{new Cookie("oauth_state", stateCli)});

    Optional<OAuthState> extractedCli = helperInsecure.validateAndExtractState(reqCli);
    assertThat(extractedCli.isPresent()).isTrue();
    assertThat(extractedCli.get()).isEqualTo(OAuthState.CLI_LOGIN);
  }

  @Test
  public void testValidateMismatchedNonce() {
    String state1 = helperInsecure.createStateValue(OAuthState.HOME);
    String state2 = helperInsecure.createStateValue(OAuthState.HOME);

    HttpServletRequest req = createFakeRequest(
        Map.of("state", state1),
        new Cookie[]{new Cookie("oauth_state", state2)});

    Optional<OAuthState> extracted = helperInsecure.validateAndExtractState(req);
    assertThat(extracted.isPresent()).isFalse();
  }

  @Test
  public void testValidateMissingCookie() {
    String state = helperInsecure.createStateValue(OAuthState.HOME);
    HttpServletRequest reqNoCookies = createFakeRequest(Map.of("state", state), null);
    assertThat(helperInsecure.validateAndExtractState(reqNoCookies).isPresent()).isFalse();

    HttpServletRequest reqOtherCookie = createFakeRequest(
        Map.of("state", state),
        new Cookie[]{new Cookie("other_cookie", state)});
    assertThat(helperInsecure.validateAndExtractState(reqOtherCookie).isPresent()).isFalse();
  }

  @Test
  public void testValidateMissingStateParam() {
    String state = helperInsecure.createStateValue(OAuthState.HOME);
    HttpServletRequest reqNoParam = createFakeRequest(
        Map.of(),
        new Cookie[]{new Cookie("oauth_state", state)});
    assertThat(helperInsecure.validateAndExtractState(reqNoParam).isPresent()).isFalse();

    HttpServletRequest reqEmptyParam = createFakeRequest(
        Map.of("state", ""),
        new Cookie[]{new Cookie("oauth_state", state)});
    assertThat(helperInsecure.validateAndExtractState(reqEmptyParam).isPresent()).isFalse();
  }

  @Test
  public void testValidateLegacyStaticStateWithoutNonceRejected() {
    // SV-02 vulnerability scenario: static "HOME" or "CLI_LOGIN" state
    HttpServletRequest req = createFakeRequest(
        Map.of("state", "HOME"),
        new Cookie[]{new Cookie("oauth_state", "HOME")});
    assertThat(helperInsecure.validateAndExtractState(req).isPresent()).isFalse();

    HttpServletRequest reqCli = createFakeRequest(
        Map.of("state", "CLI_LOGIN"),
        new Cookie[]{new Cookie("oauth_state", "CLI_LOGIN")});
    assertThat(helperInsecure.validateAndExtractState(reqCli).isPresent()).isFalse();
  }

  @Test
  public void testValidateTamperedDestination() {
    // Same nonce, but destination changed
    String nonce = "1234567890abcdef1234567890abcdef";
    HttpServletRequest req = createFakeRequest(
        Map.of("state", "HOME:" + nonce),
        new Cookie[]{new Cookie("oauth_state", "CLI_LOGIN:" + nonce)});
    assertThat(helperInsecure.validateAndExtractState(req).isPresent()).isFalse();
  }

  @Test
  public void testValidateInvalidOrMalformedStates() {
    String[] malformed = {
        ":1234567890abcdef1234567890abcdef",
        "HOME:",
        "HOME:nonce:extra",
    };
    for (String state : malformed) {
      HttpServletRequest req = createFakeRequest(
          Map.of("state", state),
          new Cookie[]{new Cookie("oauth_state", state)});
      assertThat(helperInsecure.validateAndExtractState(req).isPresent()).isFalse();
    }
  }

  @Test
  public void testFromStringFallbackToHome() {
    assertThat(OAuthState.fromString("UNKNOWN:1234567890abcdef")).isEqualTo(OAuthState.HOME);
    assertThat(OAuthState.fromString(null)).isEqualTo(OAuthState.HOME);
  }

  @Test
  public void testValidateMultipleCookiesWithOneMatching() {
    String validState = helperInsecure.createStateValue(OAuthState.HOME);
    HttpServletRequest req = createFakeRequest(
        Map.of("state", validState),
        new Cookie[]{
            new Cookie("other", "foo"),
            new Cookie("oauth_state", "HOME:oldnonce1234567890abcdef"),
            new Cookie("oauth_state", validState)
        });
    Optional<OAuthState> extracted = helperInsecure.validateAndExtractState(req);
    assertThat(extracted.isPresent()).isTrue();
    assertThat(extracted.get()).isEqualTo(OAuthState.HOME);
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
}
