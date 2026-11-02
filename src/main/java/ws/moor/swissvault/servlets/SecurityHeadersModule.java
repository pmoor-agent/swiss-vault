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
package ws.moor.swissvault.servlets;

import com.google.common.net.HttpHeaders;
import com.google.inject.Inject;
import com.google.inject.Singleton;
import com.google.inject.servlet.ServletModule;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class SecurityHeadersModule extends ServletModule {

  @Override
  protected void configureServlets() {
    filter("/*").through(SecurityHeadersFilter.class);
  }

  @Singleton
  private static class SecurityHeadersFilter implements Filter {

    private static final String STRICT_TRANSPORT_SECURITY_VALUE = "max-age=7776000; includeSubDomains";
    private static final String CONTENT_SECURITY_POLICY_VALUE =
        "default-src 'none'; script-src 'self'; style-src 'self'; "
            + "connect-src 'self'; img-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

    @Inject
    SecurityHeadersFilter() {}

    @Override
    public void init(FilterConfig filterConfig) {}

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
        throws IOException, ServletException {
      if (response instanceof HttpServletResponse) {
        HttpServletResponse httpResponse = (HttpServletResponse) response;
        httpResponse.setHeader(HttpHeaders.CACHE_CONTROL, "no-store");
        httpResponse.setHeader(HttpHeaders.STRICT_TRANSPORT_SECURITY, STRICT_TRANSPORT_SECURITY_VALUE);
        httpResponse.setHeader(HttpHeaders.X_CONTENT_TYPE_OPTIONS, "nosniff");
        httpResponse.setHeader(HttpHeaders.CONTENT_SECURITY_POLICY, CONTENT_SECURITY_POLICY_VALUE);
      }
      chain.doFilter(request, response);
    }

    @Override
    public void destroy() {}
  }
}
