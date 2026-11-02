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
    String accessToken = sendAndExtractField(tokenRequest, "token", "access_token");

    HttpRequest userinfoRequest = HttpRequest.newBuilder()
        .uri(URI.create("https://www.googleapis.com/oauth2/v1/userinfo"))
        .timeout(HTTP_TIMEOUT)
        .header("Authorization", String.format("Bearer %s", accessToken))
        .GET()
        .build();
    String id = sendAndExtractField(userinfoRequest, "userinfo", "id");

    return UserId.fromString(id);
  }

  private String sendAndExtractField(HttpRequest request, String requestType, String fieldName) throws IOException {
    HttpResponse<String> response;
    try {
      response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      throw new IOException("Interrupted while fetching " + ("token".equals(requestType) ? "OAuth token" : requestType), e);
    }
    if (response.statusCode() != 200) {
      throw new IOException("OAuth " + requestType + " request failed with status " + response.statusCode());
    }

    try {
      String body = response.body();
      if (body == null) {
        throw new IOException("OAuth " + requestType + " response body was null");
      }
      JsonObject object = jsonParser.parse(body).getAsJsonObject();
      if (!object.has(fieldName) || object.get(fieldName).isJsonNull()) {
        throw new IOException("OAuth " + requestType + " response missing " + fieldName);
      }
      if (!object.get(fieldName).isJsonPrimitive()) {
        throw new IOException("OAuth " + requestType + " response " + fieldName + " is not a primitive");
      }
      String value = object.get(fieldName).getAsString();
      if (value.isEmpty()) {
        throw new IOException("OAuth " + requestType + " response contains empty " + fieldName);
      }
      return value;
    } catch (JsonParseException | IllegalStateException | UnsupportedOperationException e) {
      throw new IOException("Failed to parse OAuth " + requestType + " response: " + e.getMessage(), e);
    }
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
