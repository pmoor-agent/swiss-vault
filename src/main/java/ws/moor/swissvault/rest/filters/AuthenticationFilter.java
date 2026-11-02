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
package ws.moor.swissvault.rest.filters;

import com.google.common.net.MediaType;
import com.google.inject.Inject;
import ws.moor.rest.RestAction;
import ws.moor.rest.RestFilter;
import ws.moor.rest.annotations.PreFilter;
import ws.moor.swissvault.config.Config;
import ws.moor.swissvault.domain.PermissionDeniedException;

import javax.servlet.http.HttpServletRequest;

public class AuthenticationFilter implements RestFilter {

  private final boolean secureOnly;
  private final AclService aclService;

  @Inject
  AuthenticationFilter(
      @Config("secure_only") boolean secureOnly,
      AclService aclService) {
    this.secureOnly = secureOnly;
    this.aclService = aclService;
  }

  @PreFilter
  void pre(HttpServletRequest request, Class<? extends RestAction> actionClass) throws PermissionDeniedException {
    if (secureOnly && !"https".equalsIgnoreCase(request.getScheme())) {
      throw new PermissionDeniedException("only https supported");
    }

    String secFetchSite = request.getHeader("Sec-Fetch-Site");
    if (secFetchSite != null
        && !"same-origin".equalsIgnoreCase(secFetchSite)
        && !"none".equalsIgnoreCase(secFetchSite)) {
      throw new PermissionDeniedException("cross-site request rejected");
    }

    String method = request.getMethod();
    if ("POST".equalsIgnoreCase(method) || "PUT".equalsIgnoreCase(method)) {
      if (!isJsonContentType(request.getContentType())) {
        throw new PermissionDeniedException("application/json content type required");
      }
    }

    AuthorizationRequired annotation = actionClass.getAnnotation(AuthorizationRequired.class);
    if (annotation == null) {
      throw new PermissionDeniedException("no authorization annotation");
    }

    annotation.type().assertAllowed(aclService);
  }

  private static boolean isJsonContentType(String contentType) {
    if (contentType == null) {
      return false;
    }
    try {
      return MediaType.parse(contentType).withoutParameters().is(MediaType.JSON_UTF_8.withoutParameters());
    } catch (IllegalArgumentException e) {
      return false;
    }
  }
}
