package ws.moor;

import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import ws.moor.categories.Integration;
import ws.moor.swissvault.auth.TestCookies;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;

import static com.google.common.truth.Truth.assertThat;
import static com.google.common.truth.Truth.assertWithMessage;

@Category(Integration.class)
public class EndToEndTest {

  @BeforeClass
  public static void waitForDevServer() throws InterruptedException {
    DevServer.awaitStartup();
  }

  @Test
  public void initialAuthRedirect() throws IOException {
    HttpURLConnection connection = (HttpURLConnection) new URL(DevServer.BASE_URL + "/").openConnection();
    connection.setInstanceFollowRedirects(false);

    assertThat(connection.getResponseCode()).isEqualTo(HttpURLConnection.HTTP_MOVED_TEMP);
    String location = connection.getHeaderField("Location");
    assertThat(location).startsWith("https://accounts.google.com/o/oauth2/auth");
    assertThat(location).contains("state=HOME:");
    assertThat(connection.getHeaderField("Cache-Control")).isEqualTo("no-store");
    assertThat(connection.getHeaderField("Strict-Transport-Security")).isEqualTo("max-age=7776000; includeSubDomains");
    assertThat(connection.getHeaderField("X-Content-Type-Options")).isEqualTo("nosniff");
    assertThat(connection.getHeaderField("Content-Security-Policy")).contains("frame-ancestors 'none'");

    String setCookie = connection.getHeaderField("Set-Cookie");
    assertThat(setCookie).isNotNull();
    assertThat(setCookie).contains("oauth_state=HOME:");
    assertThat(setCookie).contains("Path=/");
    assertThat(setCookie).contains("HttpOnly");
    assertThat(setCookie).contains("SameSite=Lax");

    connection.disconnect();
  }

  @Test
  public void cliLoginSecurityHeaders() throws IOException {
    HttpURLConnection connection = (HttpURLConnection) new URL(DevServer.BASE_URL + "/cli-login").openConnection();
    connection.setRequestProperty("Cookie", "auth=" + TestCookies.authCookieValue("test-user-sv03"));
    connection.setInstanceFollowRedirects(false);

    assertThat(connection.getResponseCode()).isEqualTo(HttpURLConnection.HTTP_OK);
    assertThat(connection.getHeaderField("Cache-Control")).isEqualTo("no-store");
    assertThat(connection.getHeaderField("Strict-Transport-Security")).isEqualTo("max-age=7776000; includeSubDomains");
    assertThat(connection.getHeaderField("X-Content-Type-Options")).isEqualTo("nosniff");
    String csp = connection.getHeaderField("Content-Security-Policy");
    assertThat(csp).isNotNull();
    assertThat(csp).contains("frame-ancestors 'none'");
    assertThat(csp).contains("default-src 'none'");
    assertThat(csp).contains("base-uri 'none'");
    assertThat(csp).contains("form-action 'none'");
    assertThat(csp).contains("style-src 'self'");
    assertThat(csp).doesNotContain("'unsafe-inline'");

    connection.disconnect();
  }

  @Test
  public void cliLoginAuthRedirect() throws IOException {
    HttpURLConnection connection = (HttpURLConnection) new URL(DevServer.BASE_URL + "/cli-login").openConnection();
    connection.setInstanceFollowRedirects(false);

    assertThat(connection.getResponseCode()).isEqualTo(HttpURLConnection.HTTP_MOVED_TEMP);
    String location = connection.getHeaderField("Location");
    assertThat(location).startsWith("https://accounts.google.com/o/oauth2/auth");
    assertThat(location).contains("state=CLI_LOGIN:");

    String setCookie = connection.getHeaderField("Set-Cookie");
    assertThat(setCookie).isNotNull();
    assertThat(setCookie).contains("oauth_state=CLI_LOGIN:");
    assertThat(setCookie).contains("Path=/");
    assertThat(setCookie).contains("HttpOnly");
    assertThat(setCookie).contains("SameSite=Lax");

    connection.disconnect();
  }

  @Test
  public void logoutClearsCookieAndRendersPage() throws IOException {
    HttpURLConnection connection = (HttpURLConnection) new URL(DevServer.BASE_URL + "/logout").openConnection();
    connection.setRequestProperty("Cookie", "auth=" + TestCookies.authCookieValue("test-user-logout"));
    connection.setInstanceFollowRedirects(false);

    assertThat(connection.getResponseCode()).isEqualTo(HttpURLConnection.HTTP_OK);
    assertThat(connection.getContentType()).matches("(?i)text/html;\\s*charset=utf-8");
    assertThat(connection.getHeaderField("Cache-Control")).isEqualTo("no-store");
    assertThat(connection.getHeaderField("Strict-Transport-Security")).isEqualTo("max-age=7776000; includeSubDomains");
    assertThat(connection.getHeaderField("X-Content-Type-Options")).isEqualTo("nosniff");

    String setCookie = connection.getHeaderField("Set-Cookie");
    assertThat(setCookie).isNotNull();
    assertThat(setCookie).isEqualTo("auth=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax");

    StringBuilder body = new StringBuilder();
    try (BufferedReader reader = new BufferedReader(new InputStreamReader(connection.getInputStream(), StandardCharsets.UTF_8))) {
      String line;
      while ((line = reader.readLine()) != null) {
        body.append(line).append("\n");
      }
    }
    assertThat(body.toString()).contains("<title>Swiss Vault - Logged Out</title>");
    assertThat(body.toString()).contains("<h2>Logged Out</h2>");
    assertThat(body.toString()).contains("<p>You have been logged out of Swiss Vault.</p>");
    assertThat(body.toString()).contains("<p><a href=\"/\">Log in again</a></p>");

    connection.disconnect();
  }

  @Test
  public void oauthCallbackRejectsMissingOrMismatchedState() throws IOException {
    // 1. Missing cookie and state param
    HttpURLConnection conn1 = (HttpURLConnection) new URL(DevServer.BASE_URL + "/oauth2callback").openConnection();
    conn1.setInstanceFollowRedirects(false);
    assertThat(conn1.getResponseCode()).isEqualTo(HttpURLConnection.HTTP_BAD_REQUEST);
    assertThat(conn1.getHeaderField("Set-Cookie")).contains("oauth_state=; Max-Age=0");
    conn1.disconnect();

    // 2. State param present but cookie missing
    HttpURLConnection conn2 = (HttpURLConnection) new URL(
        DevServer.BASE_URL + "/oauth2callback?code=fake_code&state=HOME:1234567890abcdef1234567890abcdef")
        .openConnection();
    conn2.setInstanceFollowRedirects(false);
    assertThat(conn2.getResponseCode()).isEqualTo(HttpURLConnection.HTTP_BAD_REQUEST);
    conn2.disconnect();

    // 3. Cookie and state param mismatched
    HttpURLConnection conn3 = (HttpURLConnection) new URL(
        DevServer.BASE_URL + "/oauth2callback?code=fake_code&state=HOME:1234567890abcdef1234567890abcdef")
        .openConnection();
    conn3.setRequestProperty("Cookie", "oauth_state=HOME:differentnonce1234567890abcdef");
    conn3.setInstanceFollowRedirects(false);
    assertThat(conn3.getResponseCode()).isEqualTo(HttpURLConnection.HTTP_BAD_REQUEST);
    conn3.disconnect();

    // 4. Legacy static state without nonce (SV-02 attack attempt)
    HttpURLConnection conn4 = (HttpURLConnection) new URL(
        DevServer.BASE_URL + "/oauth2callback?code=attacker_code&state=HOME")
        .openConnection();
    conn4.setRequestProperty("Cookie", "oauth_state=HOME");
    conn4.setInstanceFollowRedirects(false);
    assertThat(conn4.getResponseCode()).isEqualTo(HttpURLConnection.HTTP_BAD_REQUEST);
    conn4.disconnect();
  }

  @Test
  public void pythonClientIntegration() throws Exception {
    ProcessBuilder pb = new ProcessBuilder("python3", "client/test_client.py", DevServer.BASE_URL);
    pb.redirectErrorStream(true);
    Process process = pb.start();

    StringBuilder output = new StringBuilder();
    try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
      String line;
      while ((line = reader.readLine()) != null) {
        output.append(line).append("\n");
      }
    }
    int exitCode = process.waitFor();
    assertWithMessage("Python integration test failed:\n" + output)
        .that(exitCode).isEqualTo(0);
  }
}
