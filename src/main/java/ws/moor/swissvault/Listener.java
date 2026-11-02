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
package ws.moor.swissvault;

import com.google.inject.Guice;
import com.google.inject.Injector;
import com.google.inject.Stage;
import com.google.inject.servlet.GuiceServletContextListener;
import ws.moor.common.ClockModule;
import ws.moor.swissvault.auth.AuthModule;
import ws.moor.swissvault.config.ConfigurationModule;
import ws.moor.swissvault.rest.RestApiModule;
import ws.moor.swissvault.servlets.HomePageModule;
import ws.moor.swissvault.servlets.SecurityHeadersModule;

public class Listener extends GuiceServletContextListener {

  @Override
  protected Injector getInjector() {
    return Guice.createInjector(Stage.PRODUCTION,
        new AppEngineModule(),
        new ConfigurationModule(),
        new RestApiModule(),
        new SecurityHeadersModule(),
        new HomePageModule(),
        new AuthModule(),
        new ClockModule());
  }
}
