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
package ws.moor.swissvault.persistence;

import com.google.appengine.api.datastore.*;
import com.google.common.collect.Lists;
import com.google.gson.JsonObject;
import com.google.inject.Inject;
import ws.moor.swissvault.domain.EncryptedValue;
import ws.moor.swissvault.persistence.model.DbSecret;
import ws.moor.swissvault.persistence.model.DbSecretProperty;

import java.util.List;

public class SecretRepository {

  private final DatastoreService ds;

  @Inject
  SecretRepository(DatastoreService ds) {
    this.ds = ds;
  }

  public DbSecret newSecret(Transaction transaction, long keyId, JsonObject json) {
    EncryptedValue name = EncryptedValue.fromJsonObject(json.getAsJsonObject("name"));
    EncryptedValue description = EncryptedValue.fromJsonObject(json.getAsJsonObject("description"));

    DbSecret dbSecret = DbSecret.newDbSecret(keyId, name, description);
    ds.put(transaction, dbSecret.entity);
    return dbSecret;
  }

  public DbSecret getSecret(Transaction transaction, long keyId, long secretId) throws EntityNotFoundException {
    Key key = KeyFactory.createKey(
        KeyFactory.createKey("Key", keyId),
        "Secret", secretId);
    return new DbSecret(ds.get(transaction, key));
  }

  public DbSecretProperty getProperty(Transaction transaction, long keyId, long secretId, long propertyId)
      throws EntityNotFoundException {
    Key key = KeyFactory.createKey(KeyFactory.createKey(
        KeyFactory.createKey("Key", keyId),
        "Secret", secretId),
        "SecretProperty", propertyId);
    return new DbSecretProperty(ds.get(transaction, key));
  }

  public DbSecretProperty newSecretProperty(Transaction transaction, DbSecret secret, JsonObject json) {
    EncryptedValue name = EncryptedValue.fromJsonObject(json.getAsJsonObject("name"));
    EncryptedValue value = EncryptedValue.fromJsonObject(json.getAsJsonObject("value"));

    DbSecretProperty dbSecretProperty = DbSecretProperty.newDbSecret(secret.entity.getKey(), name, value);
    ds.put(transaction, dbSecretProperty.entity);
    return dbSecretProperty;
  }

  public List<DbSecret> listSecrets(Transaction transaction, long keyId) {
    Query q = new Query("Secret");
    q.setAncestor(KeyFactory.createKey("Key", keyId));
    q.addSort(Entity.KEY_RESERVED_PROPERTY, Query.SortDirection.ASCENDING);
    PreparedQuery pq = ds.prepare(transaction, q);

    List<DbSecret> result = Lists.newArrayList();
    for (Entity entity : pq.asIterable()) {
      result.add(new DbSecret(entity));
    }
    return result;
  }

  public List<DbSecretProperty> listSecretProperties(Transaction transaction, long keyId, long secretId) {
    Query q = new Query("SecretProperty");
    q.setAncestor(KeyFactory.createKey(KeyFactory.createKey("Key", keyId), "Secret", secretId));
    q.addSort(Entity.KEY_RESERVED_PROPERTY, Query.SortDirection.ASCENDING);
    PreparedQuery pq = ds.prepare(transaction, q);

    List<DbSecretProperty> result = Lists.newArrayList();
    for (Entity entity : pq.asIterable()) {
      result.add(new DbSecretProperty(entity));
    }
    return result;
  }

  public void deleteProperty(Transaction t, long keyId, long secretId, long propertyId) {
    Key propertyKey = KeyFactory.createKey(
        KeyFactory.createKey(
            KeyFactory.createKey("Key", keyId),
            "Secret", secretId),
        "SecretProperty", propertyId);
    ds.delete(t, propertyKey);
  }

  public void deleteSecret(Transaction t, long keyId, long secretId) {
    Key secretKey = KeyFactory.createKey(
            KeyFactory.createKey("Key", keyId),
            "Secret", secretId);

    Query q = new Query("SecretProperty");
    q.setAncestor(secretKey);
    q.setKeysOnly();
    PreparedQuery pq = ds.prepare(t, q);

    List<Key> keys = Lists.newArrayList();
    keys.add(secretKey);
    for (Entity property : pq.asIterable()) {
      keys.add(property.getKey());
    }
    ds.delete(t, keys);
  }

  public void update(Transaction t, DbSecretProperty property) {
    ds.put(t, property.entity);
  }

  public void update(Transaction t, DbSecret secret) {
    ds.put(t, secret.entity);
  }
}
