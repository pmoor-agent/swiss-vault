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
import com.google.common.base.Preconditions;
import com.google.common.base.Strings;
import com.google.common.io.BaseEncoding;
import com.google.inject.Inject;
import com.google.inject.Singleton;
import ws.moor.swissvault.config.Config;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Duration;

@Singleton
public class OAuthStateHelper {

  public static final String COOKIE_NAME = "oauth_state";
  public static final Duration COOKIE_EXPIRATION = Duration.ofMinutes(10);
  private static final int NONCE_BYTE_COUNT = 32;

  private final boolean secureOnly;
  private final SecureRandom secureRandom;

  @Inject
  public OAuthStateHelper(@Config("secure_only") boolean secureOnly) {
    this(secureOnly, new SecureRandom());
  }

  OAuthStateHelper(boolean secureOnly, SecureRandom secureRandom) {
    this.secureOnly = secureOnly;
    this.secureRandom = Preconditions.checkNotNull(secureRandom);
  }

  public String createStateValue(OAuthState state) {
    Preconditions.checkNotNull(state);
    byte[] nonceBytes = new byte[NONCE_BYTE_COUNT];
    secureRandom.nextBytes(nonceBytes);
    String nonce = BaseEncoding.base16().lowerCase().encode(nonceBytes);
    return state.name() + ":" + nonce;
  }

  public String createCookieHeader(String stateValue) {
    Preconditions.checkNotNull(stateValue);
    String header = String.format("%s=%s; Max-Age=%d; Path=/; HttpOnly; SameSite=Lax",
        COOKIE_NAME, stateValue, COOKIE_EXPIRATION.getSeconds());
    if (secureOnly) {
      header += "; Secure";
    }
    return header;
  }

  public String createClearCookieHeader() {
    String header = String.format("%s=; Max-Age=0; Path=/; HttpOnly; SameSite=Lax", COOKIE_NAME);
    if (secureOnly) {
      header += "; Secure";
    }
    return header;
  }

  public Optional<OAuthState> validateAndExtractState(HttpServletRequest request) {
    String stateParam = request.getParameter("state");
    if (Strings.isNullOrEmpty(stateParam)) {
      return Optional.absent();
    }

    int colonIndex = stateParam.indexOf(':');
    if (colonIndex <= 0 || colonIndex != stateParam.lastIndexOf(':') || colonIndex == stateParam.length() - 1) {
      return Optional.absent();
    }

    Cookie[] cookies = request.getCookies();
    if (cookies == null) {
      return Optional.absent();
    }

    for (Cookie cookie : cookies) {
      if (COOKIE_NAME.equals(cookie.getName()) && cookie.getValue() != null) {
        if (MessageDigest.isEqual(
            stateParam.getBytes(StandardCharsets.UTF_8),
            cookie.getValue().getBytes(StandardCharsets.UTF_8))) {
          return Optional.of(OAuthState.fromString(stateParam));
        }
      }
    }

    return Optional.absent();
  }
}
