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

import com.google.common.base.Optional;
import com.google.inject.AbstractModule;
import com.google.inject.Provides;
import com.google.inject.servlet.RequestScoped;
import com.google.inject.servlet.ServletModule;

import javax.servlet.http.HttpServletRequest;

public class AuthModule extends AbstractModule {
  @Override
  protected void configure() {
    bind(OAuthStateHelper.class);
    install(new ServletModule() {
      @Override protected void configureServlets() {
        serve(OAuthCallbackServlet.PATH).with(OAuthCallbackServlet.class);
        serve(CliLoginServlet.PATH).with(CliLoginServlet.class);
        serve(LogoutServlet.PATH).with(LogoutServlet.class);
      }
    });
  }
  
  @Provides
  @RequestScoped
  @AuthenticatedUser
  private Optional<UserId> provideUserId(AuthCookieFactory cookieFactory, HttpServletRequest request) {
    return Optional.fromNullable(cookieFactory.extractUserId(request));
  }

  @Provides
  @RequestScoped
  @AuthenticatedUser
  private UserId provideUserId(@AuthenticatedUser Optional<UserId> optionalUserId) {
    return optionalUserId.get();
  }
}
