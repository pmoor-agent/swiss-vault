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
package ws.moor.swissvault.rest.filters;

import com.google.common.base.Optional;
import org.junit.Before;
import org.junit.Test;
import ws.moor.rest.RestAction;
import ws.moor.swissvault.domain.PermissionDeniedException;

import javax.servlet.http.HttpServletRequest;
import java.lang.reflect.Proxy;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertThrows;

public class AuthenticationFilterTest {

  @AuthorizationRequired(type = AccessType.USER_ID_PRESENT)
  private static class UserAction implements RestAction {}

  @AuthorizationRequired(type = AccessType.KEY_ACL_PRESENT)
  private static class KeyAclAction implements RestAction {}

  private static class UnannotatedAction implements RestAction {}

  private FakeAclService aclService;
  private AuthenticationFilter filter;

  @Before
  public void setUp() {
    aclService = new FakeAclService();
    filter = new AuthenticationFilter(false, aclService);
  }

  @Test
  public void testGetAndDeleteSucceedWithoutContentType() throws Exception {
    HttpServletRequest getReq = new RequestBuilder().method("GET").build();
    filter.pre(getReq, UserAction.class);

    HttpServletRequest deleteReq = new RequestBuilder().method("DELETE").build();
    filter.pre(deleteReq, UserAction.class);
  }

  @Test
  public void testPostAndPutSucceedWithApplicationJson() throws Exception {
    for (String method : List.of("POST", "PUT")) {
      HttpServletRequest req1 = new RequestBuilder()
          .method(method)
          .contentType("application/json")
          .build();
      filter.pre(req1, UserAction.class);

      HttpServletRequest req2 = new RequestBuilder()
          .method(method)
          .contentType("application/json; charset=UTF-8")
          .build();
      filter.pre(req2, UserAction.class);

      HttpServletRequest req3 = new RequestBuilder()
          .method(method)
          .contentType("application/json; charset=utf-8")
          .build();
      filter.pre(req3, UserAction.class);
    }
  }

  @Test
  public void testPostAndPutRejectMissingContentType() {
    for (String method : List.of("POST", "PUT")) {
      HttpServletRequest req = new RequestBuilder().method(method).build();
      PermissionDeniedException thrown = assertThrows(
          PermissionDeniedException.class,
          () -> filter.pre(req, UserAction.class));
      assertThat(thrown).hasMessageThat().isEqualTo("application/json content type required");
    }
  }

  @Test
  public void testPostAndPutRejectInvalidContentTypes() {
    List<String> invalidContentTypes = List.of(
        "",
        "   ",
        "text/plain",
        "text/plain; charset=utf-8",
        "application/x-www-form-urlencoded",
        "multipart/form-data",
        "multipart/form-data; boundary=something",
        "application/xml",
        "text/html",
        "malformed",
        "invalid/content/type",
        ";;");

    for (String method : List.of("POST", "PUT")) {
      for (String contentType : invalidContentTypes) {
        HttpServletRequest req = new RequestBuilder()
            .method(method)
            .contentType(contentType)
            .build();
        PermissionDeniedException thrown = assertThrows(
            "Expected method " + method + " with Content-Type '" + contentType + "' to be rejected",
            PermissionDeniedException.class,
            () -> filter.pre(req, UserAction.class));
        assertThat(thrown).hasMessageThat().isEqualTo("application/json content type required");
      }
    }
  }

  @Test
  public void testAllowedSecFetchSiteHeaders() throws Exception {
    List<String> allowedHeaders = List.of("same-origin", "SAME-ORIGIN", "none", "NONE");
    for (String header : allowedHeaders) {
      HttpServletRequest req = new RequestBuilder()
          .method("GET")
          .header("Sec-Fetch-Site", header)
          .build();
      filter.pre(req, UserAction.class);
    }

    // Absence of Sec-Fetch-Site (e.g. non-browser clients)
    HttpServletRequest reqWithoutHeader = new RequestBuilder()
        .method("GET")
        .build();
    filter.pre(reqWithoutHeader, UserAction.class);
  }

  @Test
  public void testSecFetchSiteCrossSiteAndSameSiteRejected() {
    List<String> rejectedHeaders = List.of("cross-site", "CROSS-SITE", "same-site", "SAME-SITE", "unknown");
    List<String> methods = List.of("GET", "POST", "PUT", "DELETE");

    for (String method : methods) {
      for (String headerVal : rejectedHeaders) {
        HttpServletRequest req = new RequestBuilder()
            .method(method)
            .contentType("application/json")
            .header("Sec-Fetch-Site", headerVal)
            .build();
        PermissionDeniedException thrown = assertThrows(
            "Expected method " + method + " with Sec-Fetch-Site '" + headerVal + "' to be rejected",
            PermissionDeniedException.class,
            () -> filter.pre(req, UserAction.class));
        assertThat(thrown).hasMessageThat().isEqualTo("cross-site request rejected");
      }
    }
  }

  @Test
  public void testSecureOnlyRejectsHttpAndAllowsHttps() throws Exception {
    AuthenticationFilter secureFilter = new AuthenticationFilter(true, aclService);

    HttpServletRequest httpReq = new RequestBuilder().scheme("http").method("GET").build();
    PermissionDeniedException thrown = assertThrows(
        PermissionDeniedException.class,
        () -> secureFilter.pre(httpReq, UserAction.class));
    assertThat(thrown).hasMessageThat().isEqualTo("only https supported");

    HttpServletRequest httpsReq = new RequestBuilder().scheme("https").method("GET").build();
    secureFilter.pre(httpsReq, UserAction.class);
  }

  @Test
  public void testNonSecureOnlyAllowsHttpAndHttps() throws Exception {
    AuthenticationFilter insecureFilter = new AuthenticationFilter(false, aclService);

    HttpServletRequest httpReq = new RequestBuilder().scheme("http").method("GET").build();
    insecureFilter.pre(httpReq, UserAction.class);

    HttpServletRequest httpsReq = new RequestBuilder().scheme("https").method("GET").build();
    insecureFilter.pre(httpsReq, UserAction.class);
  }

  @Test
  public void testMissingAuthorizationAnnotationThrows() {
    HttpServletRequest req = new RequestBuilder().method("GET").build();
    PermissionDeniedException thrown = assertThrows(
        PermissionDeniedException.class,
        () -> filter.pre(req, UnannotatedAction.class));
    assertThat(thrown).hasMessageThat().isEqualTo("no authorization annotation");
  }

  @Test
  public void testAuthorizationAnnotationChecked() throws Exception {
    HttpServletRequest req = new RequestBuilder().method("GET").build();

    assertThat(aclService.assertHasUserIdCalled).isFalse();
    filter.pre(req, UserAction.class);
    assertThat(aclService.assertHasUserIdCalled).isTrue();

    assertThat(aclService.assertHasAclForKeyCalled).isFalse();
    filter.pre(req, KeyAclAction.class);
    assertThat(aclService.assertHasAclForKeyCalled).isTrue();
  }

  private static class FakeAclService extends AclService {
    boolean assertHasUserIdCalled = false;
    boolean assertHasAclForKeyCalled = false;

    FakeAclService() {
      super(null, Optional.absent(), null, null);
    }

    @Override
    public void assertHasUserId() {
      assertHasUserIdCalled = true;
    }

    @Override
    void assertHasAclForKey() {
      assertHasAclForKeyCalled = true;
    }
  }

  private static class RequestBuilder {
    private String scheme = "https";
    private String method = "GET";
    private String contentType = null;
    private final Map<String, String> headers = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);

    RequestBuilder scheme(String scheme) {
      this.scheme = scheme;
      return this;
    }

    RequestBuilder method(String method) {
      this.method = method;
      return this;
    }

    RequestBuilder contentType(String contentType) {
      this.contentType = contentType;
      if (contentType != null) {
        headers.put("Content-Type", contentType);
      }
      return this;
    }

    RequestBuilder header(String name, String value) {
      headers.put(name, value);
      return this;
    }

    HttpServletRequest build() {
      return (HttpServletRequest) Proxy.newProxyInstance(
          HttpServletRequest.class.getClassLoader(),
          new Class<?>[]{HttpServletRequest.class},
          (proxy, m, args) -> {
            switch (m.getName()) {
              case "getScheme":
                return scheme;
              case "getMethod":
                return method;
              case "getContentType":
                return contentType;
              case "getHeader":
                return headers.get((String) args[0]);
              default:
                throw new UnsupportedOperationException("Not implemented in fake request: " + m.getName());
            }
          });
    }
  }
}
