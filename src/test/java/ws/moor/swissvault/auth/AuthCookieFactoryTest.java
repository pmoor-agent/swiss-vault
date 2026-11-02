package ws.moor.swissvault.auth;

import org.junit.Before;
import org.junit.Test;

import javax.crypto.spec.SecretKeySpec;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import java.lang.reflect.Proxy;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;

import static com.google.common.truth.Truth.assertThat;

public class AuthCookieFactoryTest {

  private static final SecretKeySpec HMAC_KEY = new SecretKeySpec(new byte[32], "HmacSHA256");
  private static final SecretKeySpec OTHER_KEY = new SecretKeySpec(new byte[]{
      1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
      17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32
  }, "HmacSHA256");

  private MutableClock clock;
  private AuthCookieFactory factoryInsecure;
  private AuthCookieFactory factorySecure;

  @Before
  public void setUp() {
    clock = new MutableClock(Instant.parse("2026-06-15T12:00:00Z"));
    factoryInsecure = new AuthCookieFactory(false, HMAC_KEY, clock);
    factorySecure = new AuthCookieFactory(true, HMAC_KEY, clock);
  }

  @Test
  public void testValidCookieRoundTrip() {
    UserId user = UserId.fromString("user-123");
    String cookieHeader = factoryInsecure.createCookieString(user);
    Cookie cookie = parseCookie(cookieHeader);

    HttpServletRequest req = createFakeRequest(cookie);
    UserId extracted = factoryInsecure.extractUserId(req);

    assertThat(extracted).isEqualTo(user);
  }

  @Test
  public void testPathAttributePresent() {
    String insecureHeader = factoryInsecure.createCookieString(UserId.fromString("user-1"));
    assertThat(insecureHeader).contains("; Path=/;");
    assertThat(insecureHeader).matches("^auth=[^;]+; Path=/; Max-Age=3600; HttpOnly; SameSite=Lax$");
  }

  @Test
  public void testSecureFlagToggle() {
    String insecureHeader = factoryInsecure.createCookieString(UserId.fromString("user-1"));
    assertThat(insecureHeader).doesNotContain("Secure");

    String secureHeader = factorySecure.createCookieString(UserId.fromString("user-1"));
    assertThat(secureHeader).endsWith("; Secure");
    assertThat(secureHeader).matches("^auth=[^;]+; Path=/; Max-Age=3600; HttpOnly; SameSite=Lax; Secure$");
  }

  @Test
  public void testExpiredCookieRejected() {
    UserId user = UserId.fromString("user-1");
    String cookieHeader = factoryInsecure.createCookieString(user);
    Cookie cookie = parseCookie(cookieHeader);

    // Advance clock past expiration (60 minutes + 1 second)
    clock.advance(Duration.ofMinutes(60).plusSeconds(1));

    HttpServletRequest req = createFakeRequest(cookie);
    assertThat(factoryInsecure.extractUserId(req)).isNull();
  }

  @Test
  public void testExactBoundaryExpiration() {
    UserId user = UserId.fromString("user-1");
    String cookieHeader = factoryInsecure.createCookieString(user);
    Cookie cookie = parseCookie(cookieHeader);

    // Exactly at expiration (60 minutes)
    clock.advance(Duration.ofMinutes(60));
    HttpServletRequest req = createFakeRequest(cookie);
    assertThat(factoryInsecure.extractUserId(req)).isNull();

    // Reset clock back to 59 minutes and 59 seconds after creation
    clock.setInstant(Instant.parse("2026-06-15T12:00:00Z").plus(Duration.ofMinutes(59).plusSeconds(59)));
    assertThat(factoryInsecure.extractUserId(req)).isEqualTo(user);
  }

  @Test
  public void testFutureTimestampTolerance() {
    // Cookie created 30 seconds in the future (within 1 minute skew)
    MutableClock futureClock = new MutableClock(clock.instant().plusSeconds(30));
    AuthCookieFactory futureFactory = new AuthCookieFactory(false, HMAC_KEY, futureClock);
    String cookieHeader = futureFactory.createCookieString(UserId.fromString("user-skew"));
    Cookie cookie = parseCookie(cookieHeader);

    HttpServletRequest req = createFakeRequest(cookie);
    assertThat(factoryInsecure.extractUserId(req)).isEqualTo(UserId.fromString("user-skew"));

    // Cookie created 60 seconds in the future (exact boundary of skew tolerance)
    futureClock.setInstant(clock.instant().plusSeconds(60));
    String exactSkewHeader = futureFactory.createCookieString(UserId.fromString("user-exact"));
    assertThat(factoryInsecure.extractUserId(createFakeRequest(parseCookie(exactSkewHeader))))
        .isEqualTo(UserId.fromString("user-exact"));

    // Cookie created 61 seconds in the future (exceeds 1 minute skew tolerance)
    futureClock.setInstant(clock.instant().plusSeconds(61));
    String futureHeader = futureFactory.createCookieString(UserId.fromString("user-future"));
    assertThat(factoryInsecure.extractUserId(createFakeRequest(parseCookie(futureHeader)))).isNull();

    // Cookie created 1 day in the future
    futureClock.setInstant(clock.instant().plus(Duration.ofDays(1)));
    String farFutureHeader = futureFactory.createCookieString(UserId.fromString("user-far-future"));
    assertThat(factoryInsecure.extractUserId(createFakeRequest(parseCookie(farFutureHeader)))).isNull();
  }

  @Test
  public void testTamperedSignatureRejected() {
    String cookieHeader = factoryInsecure.createCookieString(UserId.fromString("user-1"));
    Cookie cookie = parseCookie(cookieHeader);
    String[] parts = cookie.getValue().split(":");
    // Tamper with signature
    String tamperedValue = parts[0] + ":" + parts[1] + ":dGFtcGVyZWQtc2lnbmF0dXJl";

    HttpServletRequest req = createFakeRequest(new Cookie("auth", tamperedValue));
    assertThat(factoryInsecure.extractUserId(req)).isNull();
  }

  @Test
  public void testTamperedUserIdRejected() {
    String cookieHeader = factoryInsecure.createCookieString(UserId.fromString("user-1"));
    Cookie cookie = parseCookie(cookieHeader);
    String[] parts = cookie.getValue().split(":");
    // Change userId to user-2 while keeping user-1's signature
    String tamperedValue = "user-2:" + parts[1] + ":" + parts[2];

    HttpServletRequest req = createFakeRequest(new Cookie("auth", tamperedValue));
    assertThat(factoryInsecure.extractUserId(req)).isNull();
  }

  @Test
  public void testTamperedTimestampRejected() {
    String cookieHeader = factoryInsecure.createCookieString(UserId.fromString("user-1"));
    Cookie cookie = parseCookie(cookieHeader);
    String[] parts = cookie.getValue().split(":");
    // Change timestamp while keeping original signature
    long tamperedTime = Long.parseLong(parts[1]) - 1000;
    String tamperedValue = parts[0] + ":" + tamperedTime + ":" + parts[2];

    HttpServletRequest req = createFakeRequest(new Cookie("auth", tamperedValue));
    assertThat(factoryInsecure.extractUserId(req)).isNull();
  }

  @Test
  public void testWrongNumberOfPartsRejected() {
    String[] badInputs = {
        "foo",
        "a:b",
        "a:b:c:d",
        "",
        ":",
        "::",
        ":::"
    };
    for (String badInput : badInputs) {
      HttpServletRequest req = createFakeRequest(new Cookie("auth", badInput));
      assertThat(factoryInsecure.extractUserId(req)).isNull();
    }
  }

  @Test
  public void testEmptyUserIdRejected() {
    String[] badInputs = {
        ":123:c2ln",
        "::c2ln",
        ":"
    };
    for (String badInput : badInputs) {
      HttpServletRequest req = createFakeRequest(new Cookie("auth", badInput));
      assertThat(factoryInsecure.extractUserId(req)).isNull();
    }
  }

  @Test
  public void testInvalidTimestampRejected() {
    String[] badTimestamps = {
        "user:notanumber:c2ln",
        "user::c2ln",
        "user: 123 :c2ln",
        "user:999999999999999999999999999999999999999999:c2ln",
        "user:" + Long.MAX_VALUE + ":c2ln",
        "user:" + Long.MIN_VALUE + ":c2ln",
    };
    for (String badInput : badTimestamps) {
      HttpServletRequest req = createFakeRequest(new Cookie("auth", badInput));
      assertThat(factoryInsecure.extractUserId(req)).isNull();
    }
  }

  @Test
  public void testInvalidBase64SignatureRejected() {
    String[] badSignatures = {
        "user:123:%%%",
        "user:123:not-valid-base64===",
        "user:123:abc def",
        "user:123:!@#$%^&*",
    };
    for (String badInput : badSignatures) {
      HttpServletRequest req = createFakeRequest(new Cookie("auth", badInput));
      assertThat(factoryInsecure.extractUserId(req)).isNull();
    }
  }

  @Test
  public void testDifferentHmacKeyRejected() {
    String cookieHeader = factoryInsecure.createCookieString(UserId.fromString("user-1"));
    Cookie cookie = parseCookie(cookieHeader);

    AuthCookieFactory otherFactory = new AuthCookieFactory(false, OTHER_KEY, clock);
    HttpServletRequest req = createFakeRequest(cookie);
    assertThat(otherFactory.extractUserId(req)).isNull();
  }

  @Test
  public void testMissingOrNullCookie() {
    HttpServletRequest reqNoCookies = createFakeRequest();
    assertThat(factoryInsecure.extractUserId(reqNoCookies)).isNull();

    HttpServletRequest reqNullCookies = (HttpServletRequest) Proxy.newProxyInstance(
        HttpServletRequest.class.getClassLoader(),
        new Class<?>[]{HttpServletRequest.class},
        (proxy, method, args) -> null);
    assertThat(factoryInsecure.extractUserId(reqNullCookies)).isNull();

    HttpServletRequest reqNullValue = createFakeRequest(new Cookie("auth", null));
    assertThat(factoryInsecure.extractUserId(reqNullValue)).isNull();

    HttpServletRequest reqOtherCookie = createFakeRequest(new Cookie("session", "abc"));
    assertThat(factoryInsecure.extractUserId(reqOtherCookie)).isNull();
  }

  @Test
  public void testMultipleCookiesWithAuthCookie() {
    UserId user = UserId.fromString("user-multi");
    String cookieHeader = factoryInsecure.createCookieString(user);
    Cookie authCookie = parseCookie(cookieHeader);

    HttpServletRequest req = createFakeRequest(
        new Cookie("session", "xyz"),
        authCookie,
        new Cookie("tracking", "123"));

    assertThat(factoryInsecure.extractUserId(req)).isEqualTo(user);
  }

  private static Cookie parseCookie(String cookieHeader) {
    String prefix = "auth=";
    int start = cookieHeader.indexOf(prefix);
    int end = cookieHeader.indexOf(';', start);
    String value = cookieHeader.substring(start + prefix.length(), end);
    return new Cookie("auth", value);
  }

  private static HttpServletRequest createFakeRequest(Cookie... cookies) {
    return (HttpServletRequest) Proxy.newProxyInstance(
        HttpServletRequest.class.getClassLoader(),
        new Class<?>[]{HttpServletRequest.class},
        (proxy, method, args) -> {
          if ("getCookies".equals(method.getName())) {
            return cookies;
          }
          return null;
        });
  }

  private static class MutableClock extends Clock {
    private Instant instant;
    private final ZoneId zone = ZoneOffset.UTC;

    MutableClock(Instant instant) {
      this.instant = instant;
    }

    void setInstant(Instant instant) {
      this.instant = instant;
    }

    void advance(Duration duration) {
      this.instant = this.instant.plus(duration);
    }

    @Override
    public ZoneId getZone() {
      return zone;
    }

    @Override
    public Clock withZone(ZoneId zone) {
      throw new UnsupportedOperationException();
    }

    @Override
    public Instant instant() {
      return instant;
    }
  }
}
