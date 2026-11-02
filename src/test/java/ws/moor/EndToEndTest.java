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
    Truth.assertThat(connection.getHeaderField("Location")).startsWith("https://accounts.google.com/o/oauth2/auth");
    Truth.assertThat(connection.getHeaderField("Cache-Control")).isEqualTo("no-store");
    Truth.assertThat(connection.getHeaderField("Strict-Transport-Security")).isEqualTo("max-age=7776000; includeSubDomains");
    Truth.assertThat(connection.getHeaderField("X-Content-Type-Options")).isEqualTo("nosniff");
    Truth.assertThat(connection.getHeaderField("Content-Security-Policy")).contains("frame-ancestors 'none'");

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
