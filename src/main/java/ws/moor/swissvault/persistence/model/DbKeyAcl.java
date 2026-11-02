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
package ws.moor.swissvault.persistence.model;

import com.google.appengine.api.datastore.Entity;
import com.google.appengine.api.datastore.Key;
import com.google.gson.JsonObject;
import ws.moor.swissvault.auth.UserId;
import ws.moor.swissvault.domain.EncryptedValue;

import java.util.Date;
import java.util.List;

public class DbKeyAcl {

  public static final Property<UserId> userIdProperty = Property.userId("user_id");
  public static final Property<List<EncryptedValue>> encryptionsProperty = Property.encryptedValues("encryptions");

  public static final Property<Date> validFromProperty = Property.date("valid_from");

  public final Entity entity;

  public DbKeyAcl(Entity entity) {
    this.entity = entity;
  }

  public static DbKeyAcl newAcl(
      DbKey dbKey, UserId userId, List<EncryptedValue> encryptions) {
    Key parent = dbKey.entity.getKey();
    Entity entity = new Entity("KeyAcl", userId.asString(), parent);
    userIdProperty.set(entity, userId);
    encryptionsProperty.set(entity, encryptions);
    validFromProperty.set(entity, new Date());
    return new DbKeyAcl(entity);
  }

  public JsonObject toJsonObject() {
    JsonObject result = new JsonObject();
    result.addProperty("user_id", getUserId().asString());
    result.addProperty("valid_from", validFromProperty.get(entity).toString());
    return result;
  }

  @SuppressWarnings("unchecked")
  public List<EncryptedValue> getEncryptions() {
    return encryptionsProperty.get(entity);
  }

  public UserId getUserId() {
    return UserId.fromString(entity.getKey().getName());
  }

  public void update(List<EncryptedValue> encryptions) {
    encryptionsProperty.set(entity, encryptions);
  }
}
