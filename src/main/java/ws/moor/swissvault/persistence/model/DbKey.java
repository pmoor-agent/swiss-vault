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
import com.google.common.collect.Lists;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import ws.moor.swissvault.auth.UserId;
import ws.moor.swissvault.domain.EncryptedValue;
import ws.moor.swissvault.util.Obfuscator;

import java.util.Date;
import java.util.List;

import static com.google.common.base.Preconditions.checkState;

public class DbKey {

  public final Entity entity;

  private final Property<Date> creationDate = Property.date("creation-date");
  private final Property<EncryptedValue> name = Property.encryptedValue("name");
  private final Property<EncryptedValue> description = Property.encryptedValue("description");
  
  private final List<DbKeyAcl> transientAcls = Lists.newArrayList();

  public DbKey(Entity entity) {
    this.entity = entity;
  }

  public static DbKey newDbSecretKey(
      EncryptedValue name,
      EncryptedValue description) {
    DbKey dbKey = new DbKey(new Entity("Key"));
    dbKey.creationDate.set(dbKey.entity, new Date());
    dbKey.name.set(dbKey.entity, name);
    dbKey.description.set(dbKey.entity, description);
    return dbKey;
  }

//  public Reference getLocation(Obfuscator obfuscator) {
//    return new Reference(URI.create("http://localhost:8080/api/keys/" + obfuscator.obfuscateLong(entity.getKey().getId())));
//  }

  public JsonObject toJsonObject(Obfuscator obfuscator, UserId userId) {
    checkState(!transientAcls.isEmpty(), "cannot serialize a key without any ACLs");

    JsonObject object = new JsonObject();
    object.addProperty("id", obfuscator.obfuscateLong(entity.getKey().getId()));
    object.addProperty("creation-date", creationDate.get(entity).toString());
    object.add("name", name.get(entity).toJsonObject());
    object.add("description", description.get(entity).toJsonObject());
    JsonArray acls = new JsonArray();
    for (DbKeyAcl acl : transientAcls) {
      if (acl.getUserId().equals(userId)) {
        JsonArray encryptions = new JsonArray();
        for (EncryptedValue encryption : acl.getEncryptions()) {
          encryptions.add(encryption.toJsonObject());
        }
        object.add("encryptions", encryptions);
      }
      acls.add(acl.toJsonObject());
    }
    object.add("acls", acls);
    return object;
  }

  public void update(EncryptedValue name, EncryptedValue description) {
    this.name.set(entity, name);
    this.description.set(entity, description);
  }

  public void setTransientAcl(List<DbKeyAcl> dbKeyAcl) {
    transientAcls.clear();
    transientAcls.addAll(dbKeyAcl);
  }
}
