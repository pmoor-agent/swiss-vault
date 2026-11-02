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
import com.google.common.collect.ImmutableList;
import com.google.common.collect.Lists;
import com.google.common.collect.Maps;
import com.google.gson.JsonObject;
import com.google.inject.Inject;
import ws.moor.swissvault.auth.UserId;
import ws.moor.swissvault.domain.EncryptedValue;
import ws.moor.swissvault.domain.PermissionDeniedException;
import ws.moor.swissvault.persistence.model.DbKey;
import ws.moor.swissvault.persistence.model.DbKeyAcl;

import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class KeyRepository {

  private final DatastoreService ds;

  @Inject
  KeyRepository(DatastoreService ds) {
    this.ds = ds;
  }

  public List<DbKey> getKeysWithUserAcl(UserId userId) {
    Query q = new Query("KeyAcl");
    q.setFilter(new Query.FilterPredicate(
        DbKeyAcl.userIdProperty.getName(), Query.FilterOperator.EQUAL, userId.asString()));
    q.addSort(Entity.KEY_RESERVED_PROPERTY, Query.SortDirection.ASCENDING);
    PreparedQuery pq = ds.prepare(q);

    Map<Key, DbKeyAcl> map = Maps.newHashMap();
    for (Entity child : pq.asIterable(FetchOptions.Builder.withLimit(100))) {
      Key parentKey = child.getParent();
      DbKeyAcl acl = new DbKeyAcl(child);
      map.put(parentKey, acl);
    }

    List<DbKey> result = Lists.newArrayList();
    for (Entity entity : ds.get(map.keySet()).values()) {
      DbKey key = new DbKey(entity);
      key.setTransientAcl(ImmutableList.of(map.get(entity.getKey())));
      result.add(key);
    }
    return result;
  }

  public DbKey newKey(Transaction transaction, UserId userId, JsonObject postData) {
    EncryptedValue name = EncryptedValue.fromJsonObject(postData.getAsJsonObject("name"));
    EncryptedValue description = EncryptedValue.fromJsonObject(postData.getAsJsonObject("description"));
    List<EncryptedValue> encryptions = EncryptedValue.fromJsonArray(postData.getAsJsonArray("encryptions"));

    DbKey key = DbKey.newDbSecretKey(name, description);
    ds.put(transaction, key.entity);

    DbKeyAcl acl = DbKeyAcl.newAcl(key, userId, encryptions);
    ds.put(transaction, acl.entity);
    
    key.setTransientAcl(ImmutableList.of(acl));
    return key;
  }

  public void delete(Transaction transaction, long keyId) {
    Key secretKeyKey = KeyFactory.createKey("Key", keyId);
    Query q = new Query(secretKeyKey);
    q.setKeysOnly();
    PreparedQuery pq = ds.prepare(transaction, q);
    Set<Key> keys = new HashSet<Key>();
    keys.add(secretKeyKey);
    for (Entity entity : pq.asIterable()) {
      keys.add(entity.getKey());
    }
    ds.delete(transaction, keys);
  }

  public DbKey getKey(Transaction transaction, long keyId) {
    Key secretKeyKey = KeyFactory.createKey("Key", keyId);
    try {
      DbKey dbKey = new DbKey(ds.get(transaction, secretKeyKey));

      Query q = new Query("KeyAcl", secretKeyKey);
      PreparedQuery pq = ds.prepare(transaction, q);

      List<DbKeyAcl> acls = Lists.newArrayList();
      for (Entity entity : pq.asList(FetchOptions.Builder.withLimit(100))) {
        acls.add(new DbKeyAcl(entity));
      }
      
      dbKey.setTransientAcl(acls);
      return dbKey;
    } catch (EntityNotFoundException e) {
      throw new IllegalStateException("if we found an ACL the key should always be there");
    }
  }

  public DbKey updateKey(Transaction transaction, UserId userId, long keyId, JsonObject json) {
    Key keyKey = KeyFactory.createKey("Key", keyId);
    try {
      DbKey dbKey = new DbKey(ds.get(transaction, keyKey));
      EncryptedValue name = EncryptedValue.fromJsonObject(json.getAsJsonObject("name"));
      EncryptedValue description = EncryptedValue.fromJsonObject(json.getAsJsonObject("description"));
      List<EncryptedValue> encryptions = EncryptedValue.fromJsonArray(json.getAsJsonArray("encryptions"));

      dbKey.update(name, description);
      ds.put(dbKey.entity);

      Query q = new Query("KeyAcl", keyKey);
      PreparedQuery pq = ds.prepare(transaction, q);

      List<DbKeyAcl> acls = Lists.newArrayList();
      for (Entity entity : pq.asList(FetchOptions.Builder.withLimit(100))) {
        DbKeyAcl acl = new DbKeyAcl(entity);
        if (acl.getUserId().equals(userId)) {
          acl.update(encryptions);
          ds.put(acl.entity);
        }

        acls.add(acl);
      }
      dbKey.setTransientAcl(acls);
      return dbKey;
    } catch (EntityNotFoundException e) {
      throw new PermissionDeniedException("key not found");
    }
  }
}
