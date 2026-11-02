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
package ws.moor.swissvault.auth;

import com.google.common.base.Function;
import com.google.common.base.Joiner;
import com.google.common.base.Throwables;
import com.google.common.collect.ImmutableSet;
import com.google.common.collect.Iterables;
import com.google.common.collect.Maps;
import com.google.gson.JsonObject;
import com.google.gson.JsonParseException;
import com.google.gson.JsonParser;
import com.google.inject.Inject;
import ws.moor.swissvault.config.Config;
import ws.moor.swissvault.util.UriBuilder;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Map;
import java.util.Set;
import java.util.logging.Logger;

public class AuthHelper {

  private static final Logger logger = Logger.getLogger(AuthHelper.class.getName());
  private static final Duration HTTP_TIMEOUT = Duration.ofSeconds(10);

  private static final URI PROFILE_SCOPE = URI.create("https://www.googleapis.com/auth/userinfo.profile");
  private static final Set<URI> SCOPES = ImmutableSet.of(PROFILE_SCOPE);

  private final HttpClient httpClient;
  private final JsonParser jsonParser;
  private final UriBuilder uriBuilder;
  private final String clientId;
  private final String clientSecret;

  @Inject
  AuthHelper(JsonParser jsonParser, UriBuilder uriBuilder,
             @Config("oauth.client_secret") String clientSecret, @Config("oauth.client_id") String clientId) {
    this(HttpClient.newBuilder().connectTimeout(HTTP_TIMEOUT).build(), jsonParser, uriBuilder, clientSecret, clientId);
  }

  AuthHelper(HttpClient httpClient, JsonParser jsonParser, UriBuilder uriBuilder,
             String clientSecret, String clientId) {
    this.httpClient = httpClient;
    this.jsonParser = jsonParser;
    this.uriBuilder = uriBuilder;
    this.clientSecret = clientSecret;
    this.clientId = clientId;
  }

  public URI createRedirectUri(OAuthState state, String nonce) {
    return createRedirectUri(state.name() + ":" + nonce);
  }

  public URI createRedirectUri(String state) {
    Map<String, String> parameters = Maps.newHashMap();
    parameters.put("response_type", "code");
    parameters.put("client_id", clientId);
    parameters.put("redirect_uri", uriBuilder.forPath(OAuthCallbackServlet.PATH).toString());
    parameters.put("scope", Joiner.on(" ").join(SCOPES));
    parameters.put("access_type", "online");
    parameters.put("state", state);

    try {
      return new URI("https", "accounts.google.com", "/o/oauth2/auth", buildKeyValueString(parameters, false), null);
    } catch (URISyntaxException e) {
      throw new IllegalArgumentException(e);
    }
  }

  public UserId determineUserId(String code) throws IOException {
    Map<String, String> parameters = Maps.newHashMap();
    parameters.put("code", code);
    parameters.put("client_id", clientId);
    parameters.put("client_secret", clientSecret);
    parameters.put("redirect_uri", uriBuilder.forPath(OAuthCallbackServlet.PATH).toString());
    parameters.put("grant_type", "authorization_code");

    HttpRequest tokenRequest = HttpRequest.newBuilder()
        .uri(URI.create("https://accounts.google.com/o/oauth2/token"))
        .timeout(HTTP_TIMEOUT)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .POST(HttpRequest.BodyPublishers.ofString(buildKeyValueString(parameters, true)))
        .build();
    HttpResponse<String> tokenResponse;
    try {
      tokenResponse = httpClient.send(tokenRequest, HttpResponse.BodyHandlers.ofString());
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      throw new IOException("Interrupted while fetching OAuth token", e);
    }
    if (tokenResponse.statusCode() != 200) {
      throw new IOException("OAuth token request failed with status " + tokenResponse.statusCode());
    }

    String accessToken;
    try {
      String body = tokenResponse.body();
      if (body == null) {
        throw new IOException("OAuth token response body was null");
      }
      JsonObject object = jsonParser.parse(body).getAsJsonObject();
      if (!object.has("access_token") || object.get("access_token").isJsonNull()) {
        throw new IOException("OAuth token response missing access_token");
      }
      if (!object.get("access_token").isJsonPrimitive()) {
        throw new IOException("OAuth token response access_token is not a primitive");
      }
      accessToken = object.get("access_token").getAsString();
      if (accessToken.isEmpty()) {
        throw new IOException("OAuth token response contains empty access_token");
      }
    } catch (JsonParseException | IllegalStateException | UnsupportedOperationException e) {
      throw new IOException("Failed to parse OAuth token response: " + e.getMessage(), e);
    }

    HttpRequest userinfoRequest = HttpRequest.newBuilder()
        .uri(URI.create("https://www.googleapis.com/oauth2/v1/userinfo"))
        .timeout(HTTP_TIMEOUT)
        .header("Authorization", String.format("Bearer %s", accessToken))
        .GET()
        .build();
    HttpResponse<String> userinfoResponse;
    try {
      userinfoResponse = httpClient.send(userinfoRequest, HttpResponse.BodyHandlers.ofString());
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      throw new IOException("Interrupted while fetching userinfo", e);
    }
    if (userinfoResponse.statusCode() != 200) {
      throw new IOException("OAuth userinfo request failed with status " + userinfoResponse.statusCode());
    }

    String id;
    try {
      String body = userinfoResponse.body();
      if (body == null) {
        throw new IOException("OAuth userinfo response body was null");
      }
      JsonObject object = jsonParser.parse(body).getAsJsonObject();
      if (!object.has("id") || object.get("id").isJsonNull()) {
        throw new IOException("OAuth userinfo response missing id");
      }
      if (!object.get("id").isJsonPrimitive()) {
        throw new IOException("OAuth userinfo response id is not a primitive");
      }
      id = object.get("id").getAsString();
      if (id.isEmpty()) {
        throw new IOException("OAuth userinfo response contains empty id");
      }
    } catch (JsonParseException | IllegalStateException | UnsupportedOperationException e) {
      throw new IOException("Failed to parse OAuth userinfo response: " + e.getMessage(), e);
    }

    return UserId.fromString(id);
  }

  private String buildKeyValueString(Map<String, String> parameters, final boolean encode) {
    return Joiner.on('&').join(Iterables.transform(parameters.entrySet(),
        new Function<Map.Entry<String, String>, Object>() {
          @Override public String apply(Map.Entry<String, String> parameter) {
            try {
              String key = encode ? URLEncoder.encode(parameter.getKey(), "UTF-8") : parameter.getKey();
              String value = encode ? URLEncoder.encode(parameter.getValue(), "UTF-8") : parameter.getValue();
              return String.format("%s=%s", key, value);
            } catch (UnsupportedEncodingException e) {
              throw Throwables.propagate(e);
            }
          }
        }));
  }
}
