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
package ws.moor.swissvault.auth;

public enum OAuthState {
  HOME("/"),
  CLI_LOGIN(CliLoginServlet.PATH);

  private final String path;

  OAuthState(String path) {
    this.path = path;
  }

  public String getPath() {
    return path;
  }

  public static OAuthState fromString(String value) {
    if (value != null) {
      int colon = value.indexOf(':');
      String name = colon >= 0 ? value.substring(0, colon) : value;
      try {
        return OAuthState.valueOf(name);
      } catch (IllegalArgumentException ignored) {
      }
    }
    return HOME;
  }
}
