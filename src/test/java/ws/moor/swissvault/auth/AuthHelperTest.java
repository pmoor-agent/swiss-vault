package ws.moor.swissvault.auth;

import com.google.gson.JsonParser;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import ws.moor.swissvault.util.UriBuilder;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpHeaders;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.Queue;
import java.util.concurrent.CompletableFuture;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertThrows;

public class AuthHelperTest {

  private static final String CLIENT_ID = "test-client-id";
  private static final String CLIENT_SECRET = "test-client-secret";

  private FakeHttpClient httpClient;
  private UriBuilder uriBuilder;
  private AuthHelper authHelper;

  @Before
  public void setUp() {
    httpClient = new FakeHttpClient();
    uriBuilder = new UriBuilder("http", "localhost:8080");
    authHelper = new AuthHelper(httpClient, new JsonParser(), uriBuilder, CLIENT_SECRET, CLIENT_ID);
  }

  @After
  public void tearDown() {
    // Clear any interrupted status so subsequent tests aren't affected
    Thread.interrupted();
  }

  @Test
  public void testHappyPath() throws Exception {
    httpClient.enqueueResponse(200, "{\"access_token\": \"ya29.valid_token_abc\"}");
    httpClient.enqueueResponse(200, "{\"id\": \"user-google-12345\"}");

    UserId userId = authHelper.determineUserId("valid_code");

    assertThat(userId).isEqualTo(UserId.fromString("user-google-12345"));

    List<HttpRequest> sent = httpClient.getSentRequests();
    assertThat(sent).hasSize(2);

    HttpRequest tokenReq = sent.get(0);
    assertThat(tokenReq.uri()).isEqualTo(URI.create("https://accounts.google.com/o/oauth2/token"));
    assertThat(tokenReq.method()).isEqualTo("POST");
    assertThat(tokenReq.timeout()).isEqualTo(Optional.of(Duration.ofSeconds(10)));
    assertThat(tokenReq.headers().firstValue("Content-Type")).isEqualTo(Optional.of("application/x-www-form-urlencoded"));

    HttpRequest userinfoReq = sent.get(1);
    assertThat(userinfoReq.uri()).isEqualTo(URI.create("https://www.googleapis.com/oauth2/v1/userinfo"));
    assertThat(userinfoReq.method()).isEqualTo("GET");
    assertThat(userinfoReq.timeout()).isEqualTo(Optional.of(Duration.ofSeconds(10)));
    assertThat(userinfoReq.headers().firstValue("Authorization")).isEqualTo(Optional.of("Bearer ya29.valid_token_abc"));
  }

  @Test
  public void testNon200TokenResponseThrowsIOException() {
    httpClient.enqueueResponse(400, "{\"error\": \"invalid_grant\", \"error_description\": \"Code expired\"}");

    IOException thrown = assertThrows(IOException.class, () -> authHelper.determineUserId("expired_code"));
    assertThat(thrown).hasMessageThat().contains("OAuth token request failed with status 400");
    assertThat(httpClient.getSentRequests()).hasSize(1);

    httpClient.enqueueResponse(500, "Internal Server Error");
    IOException serverError = assertThrows(IOException.class, () -> authHelper.determineUserId("some_code"));
    assertThat(serverError).hasMessageThat().contains("OAuth token request failed with status 500");
  }

  @Test
  public void testMissingAccessTokenThrowsIOException() {
    String[] invalidTokenBodies = {
        "{}",
        "{\"token_type\": \"Bearer\"}",
        "{\"access_token\": null}",
        "{\"access_token\": \"\"}",
        "{\"access_token\": {}}",
        "{\"access_token\": [\"token\"]}"
    };

    for (String body : invalidTokenBodies) {
      httpClient.enqueueResponse(200, body);
      assertThrows(IOException.class, () -> authHelper.determineUserId("code"));
    }
  }

  @Test
  public void testMalformedJsonTokenResponseThrowsIOException() {
    String[] malformedBodies = {
        "not json at all",
        "{invalid json",
        "[1, 2, 3]",
        "\"string only\"",
        "12345"
    };

    for (String body : malformedBodies) {
      httpClient.enqueueResponse(200, body);
      assertThrows(IOException.class, () -> authHelper.determineUserId("code"));
    }
  }

  @Test
  public void testNon200UserinfoResponseThrowsIOException() {
    httpClient.enqueueResponse(200, "{\"access_token\": \"valid_token\"}");
    httpClient.enqueueResponse(401, "{\"error\": \"Unauthorized\"}");

    IOException thrown = assertThrows(IOException.class, () -> authHelper.determineUserId("code"));
    assertThat(thrown).hasMessageThat().contains("OAuth userinfo request failed with status 401");
    assertThat(httpClient.getSentRequests()).hasSize(2);

    httpClient.enqueueResponse(200, "{\"access_token\": \"valid_token\"}");
    httpClient.enqueueResponse(503, "Service Unavailable");
    IOException serviceError = assertThrows(IOException.class, () -> authHelper.determineUserId("code"));
    assertThat(serviceError).hasMessageThat().contains("OAuth userinfo request failed with status 503");
  }

  @Test
  public void testMissingIdInUserinfoResponseThrowsIOException() {
    String[] invalidUserinfoBodies = {
        "{}",
        "{\"name\": \"Alice\"}",
        "{\"id\": null}",
        "{\"id\": \"\"}",
        "{\"id\": {}}",
        "{\"id\": [\"user-id\"]}"
    };

    for (String body : invalidUserinfoBodies) {
      httpClient.enqueueResponse(200, "{\"access_token\": \"valid_token\"}");
      httpClient.enqueueResponse(200, body);
      assertThrows(IOException.class, () -> authHelper.determineUserId("code"));
    }
  }

  @Test
  public void testMalformedJsonUserinfoResponseThrowsIOException() {
    String[] malformedBodies = {
        "not json",
        "{broken",
        "[]",
        "123"
    };

    for (String body : malformedBodies) {
      httpClient.enqueueResponse(200, "{\"access_token\": \"valid_token\"}");
      httpClient.enqueueResponse(200, body);
      assertThrows(IOException.class, () -> authHelper.determineUserId("code"));
    }
  }

  @Test
  public void testNullResponseBodyThrowsIOException() {
    httpClient.enqueueResponse(200, null);
    assertThrows(IOException.class, () -> authHelper.determineUserId("code"));

    httpClient.enqueueResponse(200, "{\"access_token\": \"valid_token\"}");
    httpClient.enqueueResponse(200, null);
    assertThrows(IOException.class, () -> authHelper.determineUserId("code"));
  }

  @Test
  public void testInterruptedExceptionSetsThreadInterruptAndThrowsIOException() {
    httpClient.setThrowInterruptOnSend(true);

    IOException thrown = assertThrows(IOException.class, () -> authHelper.determineUserId("code"));
    assertThat(thrown).hasMessageThat().contains("Interrupted while fetching OAuth token");
    assertThat(Thread.currentThread().isInterrupted()).isTrue();
    // Clear flag
    Thread.interrupted();
  }

  @Test
  public void testCreateRedirectUri() {
    URI uriWithStateAndNonce = authHelper.createRedirectUri(OAuthState.HOME, "random-nonce-123");
    assertThat(uriWithStateAndNonce.getScheme()).isEqualTo("https");
    assertThat(uriWithStateAndNonce.getHost()).isEqualTo("accounts.google.com");
    assertThat(uriWithStateAndNonce.getPath()).isEqualTo("/o/oauth2/auth");
    assertThat(uriWithStateAndNonce.getQuery()).contains("client_id=" + CLIENT_ID);
    assertThat(uriWithStateAndNonce.getQuery()).contains("state=HOME:random-nonce-123");
    assertThat(uriWithStateAndNonce.getQuery()).contains("response_type=code");
    assertThat(uriWithStateAndNonce.getQuery()).contains("redirect_uri=http://localhost:8080/oauth2callback");

    URI uriCustom = authHelper.createRedirectUri("CUSTOM:xyz");
    assertThat(uriCustom.getQuery()).contains("state=CUSTOM:xyz");
  }

  private static class FakeHttpClient extends HttpClient {
    private final Queue<HttpResponse<String>> responses = new ArrayDeque<>();
    private final List<HttpRequest> sentRequests = new ArrayList<>();
    private boolean throwInterruptOnSend = false;

    void enqueueResponse(int statusCode, String body) {
      responses.add(new FakeHttpResponse(statusCode, body));
    }

    void setThrowInterruptOnSend(boolean throwInterrupt) {
      this.throwInterruptOnSend = throwInterrupt;
    }

    List<HttpRequest> getSentRequests() {
      return sentRequests;
    }

    @Override
    @SuppressWarnings("unchecked")
    public <T> HttpResponse<T> send(HttpRequest request, HttpResponse.BodyHandler<T> responseBodyHandler)
        throws IOException, InterruptedException {
      sentRequests.add(request);
      if (throwInterruptOnSend) {
        throw new InterruptedException("simulated interrupt");
      }
      HttpResponse<String> response = responses.poll();
      if (response == null) {
        throw new IllegalStateException("No enqueued response for request: " + request.uri());
      }
      return (HttpResponse<T>) response;
    }

    @Override
    public <T> CompletableFuture<HttpResponse<T>> sendAsync(HttpRequest request, HttpResponse.BodyHandler<T> responseBodyHandler) {
      throw new UnsupportedOperationException();
    }

    @Override
    public <T> CompletableFuture<HttpResponse<T>> sendAsync(HttpRequest request, HttpResponse.BodyHandler<T> responseBodyHandler, HttpResponse.PushPromiseHandler<T> pushPromiseHandler) {
      throw new UnsupportedOperationException();
    }

    @Override
    public Optional<java.net.CookieHandler> cookieHandler() {
      return Optional.empty();
    }

    @Override
    public Optional<Duration> connectTimeout() {
      return Optional.empty();
    }

    @Override
    public Redirect followRedirects() {
      return Redirect.NEVER;
    }

    @Override
    public Optional<java.net.ProxySelector> proxy() {
      return Optional.empty();
    }

    @Override
    public javax.net.ssl.SSLContext sslContext() {
      return null;
    }

    @Override
    public javax.net.ssl.SSLParameters sslParameters() {
      return null;
    }

    @Override
    public Optional<java.net.Authenticator> authenticator() {
      return Optional.empty();
    }

    @Override
    public Version version() {
      return Version.HTTP_2;
    }

    @Override
    public Optional<java.util.concurrent.Executor> executor() {
      return Optional.empty();
    }
  }

  private static class FakeHttpResponse implements HttpResponse<String> {
    private final int statusCode;
    private final String body;

    FakeHttpResponse(int statusCode, String body) {
      this.statusCode = statusCode;
      this.body = body;
    }

    @Override
    public int statusCode() {
      return statusCode;
    }

    @Override
    public String body() {
      return body;
    }

    @Override
    public HttpRequest request() {
      return null;
    }

    @Override
    public Optional<HttpResponse<String>> previousResponse() {
      return Optional.empty();
    }

    @Override
    public HttpHeaders headers() {
      return HttpHeaders.of(Collections.emptyMap(), (k, v) -> true);
    }

    @Override
    public Optional<javax.net.ssl.SSLSession> sslSession() {
      return Optional.empty();
    }

    @Override
    public URI uri() {
      return null;
    }

    @Override
    public HttpClient.Version version() {
      return HttpClient.Version.HTTP_2;
    }
  }
}
