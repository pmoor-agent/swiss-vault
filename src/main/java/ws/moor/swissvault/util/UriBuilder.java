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
package ws.moor.swissvault.util;

import com.google.inject.Inject;
import com.google.inject.Singleton;
import ws.moor.swissvault.config.Config;

import java.net.URI;

import static com.google.common.base.Preconditions.checkArgument;

@Singleton
public class UriBuilder {
  
  private final String scheme;
  private final String hostname;

  @Inject
  public UriBuilder(@Config("scheme") String scheme, @Config("hostname") String hostname) {
    this.scheme = scheme;
    this.hostname = hostname;
  }

  public URI forPath(String path) {
    checkArgument(path.startsWith("/"), "invalid path: " + path);
    return URI.create(String.format("%s://%s%s", scheme, hostname, path));
  }
}
