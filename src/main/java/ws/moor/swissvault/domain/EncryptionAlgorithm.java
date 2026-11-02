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
package ws.moor.swissvault.domain;

public enum EncryptionAlgorithm {
  /** Legacy: a key's raw secret, wrapped with PBKDF2-HMAC-SHA1 (1000 iterations). Still read, no longer written. */
  PBKDF2_SHA1_AES_256_CBC_HMAC_SHA256,
  /** A key's raw secret, wrapped with PBKDF2-HMAC-SHA512 (210000 iterations). */
  PBKDF2_SHA512_210000_AES_256_CBC_HMAC_SHA256,
  /** Names, descriptions and values, encrypted with a key's raw secret. */
  AES_256_CBC_HMAC_SHA256,
}
