package ws.moor;

import com.google.common.truth.Truth;
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

    Truth.assertThat(connection.getResponseCode()).isEqualTo(HttpURLConnection.HTTP_MOVED_TEMP);
    String location = connection.getHeaderField("Location");
    Truth.assertThat(location).startsWith("https://accounts.google.com/o/oauth2/auth");
    Truth.assertThat(location).contains("state=HOME:");
    Truth.assertThat(connection.getHeaderField("Cache-Control")).isEqualTo("no-store");
    Truth.assertThat(connection.getHeaderField("Strict-Transport-Security")).isEqualTo("max-age=7776000; includeSubDomains");
    Truth.assertThat(connection.getHeaderField("X-Content-Type-Options")).isEqualTo("nosniff");
    Truth.assertThat(connection.getHeaderField("Content-Security-Policy")).contains("frame-ancestors 'none'");

    String setCookie = connection.getHeaderField("Set-Cookie");
    Truth.assertThat(setCookie).isNotNull();
    Truth.assertThat(setCookie).contains("oauth_state=HOME:");
    Truth.assertThat(setCookie).contains("Path=/");
    Truth.assertThat(setCookie).contains("HttpOnly");
    Truth.assertThat(setCookie).contains("SameSite=Lax");

    connection.disconnect();
  }

  @Test
  public void cliLoginSecurityHeaders() throws IOException {
    HttpURLConnection connection = (HttpURLConnection) new URL(DevServer.BASE_URL + "/cli-login").openConnection();
    connection.setRequestProperty("Cookie", "auth=" + TestCookies.authCookieValue("test-user-sv03"));
    connection.setInstanceFollowRedirects(false);

    Truth.assertThat(connection.getResponseCode()).isEqualTo(HttpURLConnection.HTTP_OK);
    Truth.assertThat(connection.getHeaderField("Cache-Control")).isEqualTo("no-store");
    Truth.assertThat(connection.getHeaderField("Strict-Transport-Security")).isEqualTo("max-age=7776000; includeSubDomains");
    Truth.assertThat(connection.getHeaderField("X-Content-Type-Options")).isEqualTo("nosniff");
    String csp = connection.getHeaderField("Content-Security-Policy");
    Truth.assertThat(csp).isNotNull();
    Truth.assertThat(csp).contains("frame-ancestors 'none'");
    Truth.assertThat(csp).contains("default-src 'none'");
    Truth.assertThat(csp).contains("base-uri 'none'");
    Truth.assertThat(csp).contains("form-action 'none'");
    Truth.assertThat(csp).contains("style-src 'self'");
    Truth.assertThat(csp).doesNotContain("'unsafe-inline'");

    connection.disconnect();
  }

  @Test
  public void cliLoginAuthRedirect() throws IOException {
    HttpURLConnection connection = (HttpURLConnection) new URL(DevServer.BASE_URL + "/cli-login").openConnection();
    connection.setInstanceFollowRedirects(false);

    Truth.assertThat(connection.getResponseCode()).isEqualTo(HttpURLConnection.HTTP_MOVED_TEMP);
    String location = connection.getHeaderField("Location");
    Truth.assertThat(location).startsWith("https://accounts.google.com/o/oauth2/auth");
    Truth.assertThat(location).contains("state=CLI_LOGIN:");

    String setCookie = connection.getHeaderField("Set-Cookie");
    Truth.assertThat(setCookie).isNotNull();
    Truth.assertThat(setCookie).contains("oauth_state=CLI_LOGIN:");
    Truth.assertThat(setCookie).contains("Path=/");
    Truth.assertThat(setCookie).contains("HttpOnly");
    Truth.assertThat(setCookie).contains("SameSite=Lax");

    connection.disconnect();
  }

  @Test
  public void oauthCallbackRejectsMissingOrMismatchedState() throws IOException {
    // 1. Missing cookie and state param
    HttpURLConnection conn1 = (HttpURLConnection) new URL(DevServer.BASE_URL + "/oauth2callback").openConnection();
    conn1.setInstanceFollowRedirects(false);
    Truth.assertThat(conn1.getResponseCode()).isEqualTo(HttpURLConnection.HTTP_BAD_REQUEST);
    Truth.assertThat(conn1.getHeaderField("Set-Cookie")).contains("oauth_state=; Max-Age=0");
    conn1.disconnect();

    // 2. State param present but cookie missing
    HttpURLConnection conn2 = (HttpURLConnection) new URL(
        DevServer.BASE_URL + "/oauth2callback?code=fake_code&state=HOME:1234567890abcdef1234567890abcdef")
        .openConnection();
    conn2.setInstanceFollowRedirects(false);
    Truth.assertThat(conn2.getResponseCode()).isEqualTo(HttpURLConnection.HTTP_BAD_REQUEST);
    conn2.disconnect();

    // 3. Cookie and state param mismatched
    HttpURLConnection conn3 = (HttpURLConnection) new URL(
        DevServer.BASE_URL + "/oauth2callback?code=fake_code&state=HOME:1234567890abcdef1234567890abcdef")
        .openConnection();
    conn3.setRequestProperty("Cookie", "oauth_state=HOME:differentnonce1234567890abcdef");
    conn3.setInstanceFollowRedirects(false);
    Truth.assertThat(conn3.getResponseCode()).isEqualTo(HttpURLConnection.HTTP_BAD_REQUEST);
    conn3.disconnect();

    // 4. Legacy static state without nonce (SV-02 attack attempt)
    HttpURLConnection conn4 = (HttpURLConnection) new URL(
        DevServer.BASE_URL + "/oauth2callback?code=attacker_code&state=HOME")
        .openConnection();
    conn4.setRequestProperty("Cookie", "oauth_state=HOME");
    conn4.setInstanceFollowRedirects(false);
    Truth.assertThat(conn4.getResponseCode()).isEqualTo(HttpURLConnection.HTTP_BAD_REQUEST);
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
    Truth.assertWithMessage("Python integration test failed:\n" + output)
        .that(exitCode).isEqualTo(0);
  }
}
