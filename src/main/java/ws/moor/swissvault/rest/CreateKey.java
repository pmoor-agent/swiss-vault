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
package ws.moor.swissvault.rest;

import com.google.appengine.api.datastore.Transaction;
import com.google.gson.JsonObject;
import com.google.inject.Inject;
import ws.moor.rest.RestAction;
import ws.moor.rest.annotations.Execute;
import ws.moor.rest.annotations.Post;
import ws.moor.rest.annotations.RequestBody;
import ws.moor.swissvault.auth.AuthenticatedUser;
import ws.moor.swissvault.auth.UserId;
import ws.moor.swissvault.persistence.KeyRepository;
import ws.moor.swissvault.persistence.model.DbKey;
import ws.moor.swissvault.rest.filters.AccessType;
import ws.moor.swissvault.rest.filters.AuthorizationRequired;
import ws.moor.swissvault.util.Obfuscator;

import static com.google.common.base.Preconditions.checkNotNull;

@AuthorizationRequired(type = AccessType.USER_ID_PRESENT)
@Post(path = "/keys")
public class CreateKey implements RestAction {

  private final KeyRepository keyRepository;
  private final Obfuscator obfuscator;
  private final Transaction transaction;
  private final UserId currentUserId;

  @Inject
  CreateKey(KeyRepository keyRepository, Obfuscator obfuscator, Transaction transaction,
            @AuthenticatedUser UserId currentUserId) {
    this.keyRepository = keyRepository;
    this.obfuscator = obfuscator;
    this.transaction = transaction;
    this.currentUserId = currentUserId;
  }

  @Execute
  public JsonObject create(@RequestBody JsonObject entityData) {
    checkNotNull(entityData);
    DbKey key = keyRepository.newKey(transaction, currentUserId, entityData);
    transaction.commit();

    return key.toJsonObject(obfuscator, currentUserId);
  }
}
