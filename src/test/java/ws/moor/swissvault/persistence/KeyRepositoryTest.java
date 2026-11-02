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

import com.google.appengine.api.datastore.DatastoreService;
import com.google.appengine.api.datastore.DatastoreServiceFactory;
import com.google.appengine.api.datastore.Entity;
import com.google.appengine.api.datastore.Key;
import com.google.appengine.api.datastore.KeyFactory;
import com.google.appengine.api.datastore.Text;
import com.google.appengine.api.datastore.Transaction;
import com.google.appengine.tools.development.testing.LocalDatastoreServiceTestConfig;
import com.google.appengine.tools.development.testing.LocalServiceTestHelper;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import ws.moor.swissvault.auth.UserId;
import ws.moor.swissvault.domain.EncryptedValue;
import ws.moor.swissvault.domain.EncryptionAlgorithm;
import ws.moor.swissvault.domain.PermissionDeniedException;
import ws.moor.swissvault.persistence.model.DbKey;
import ws.moor.swissvault.persistence.model.DbKeyAcl;

import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertThrows;

public class KeyRepositoryTest {

  private final LocalServiceTestHelper helper =
      new LocalServiceTestHelper(new LocalDatastoreServiceTestConfig().setApplyAllHighRepJobPolicy());

  private DatastoreService ds;
  private KeyRepository repository;

  @Before
  public void setUp() {
    helper.setUp();
    ds = DatastoreServiceFactory.getDatastoreService();
    repository = new KeyRepository(ds);
  }

  @After
  public void tearDown() {
    helper.tearDown();
  }

  @Test
  public void updateKey_rollsBackBothKeyAndAclOnTransactionRollback() throws Exception {
    UserId userId = UserId.fromString("user-1");

    // 1. Create a key initially and commit it.
    Transaction createTx = ds.beginTransaction();
    JsonObject initialJson = createKeyJson("Original Key", "Original Description", "original-secret");
    DbKey createdKey = repository.newKey(createTx, userId, initialJson);
    createTx.commit();

    long keyId = createdKey.entity.getKey().getId();
    Key keyKey = KeyFactory.createKey("Key", keyId);

    // 2. Perform updateKey within a transaction, then roll it back.
    Transaction updateTx = ds.beginTransaction();
    JsonObject updatedJson = createKeyJson("Updated Key", "Updated Description", "updated-secret");
    repository.updateKey(updateTx, userId, keyId, updatedJson);
    updateTx.rollback();

    // 3. Verify datastore still holds original values for both Key and KeyAcl.
    Entity keyEntity = ds.get(keyKey);
    assertThat(getEncryptedText(keyEntity, "name"))
        .isEqualTo(getEncryptedText(initialJson, "name"));
    assertThat(getEncryptedText(keyEntity, "description"))
        .isEqualTo(getEncryptedText(initialJson, "description"));

    Key aclKey = KeyFactory.createKey(keyKey, "KeyAcl", userId.asString());
    Entity aclEntity = ds.get(aclKey);
    @SuppressWarnings("unchecked")
    List<Text> acls = (List<Text>) aclEntity.getProperty("encryptions");
    assertThat(acls).hasSize(1);
    assertThat(acls.get(0).getValue())
        .isEqualTo(getEncryptedText(initialJson.getAsJsonArray("encryptions").get(0).getAsJsonObject()));
  }

  @Test
  public void updateKey_persistsBothKeyAndAclOnTransactionCommit() throws Exception {
    UserId userId = UserId.fromString("user-1");

    // 1. Create a key initially and commit it.
    Transaction createTx = ds.beginTransaction();
    JsonObject initialJson = createKeyJson("Original Key", "Original Description", "original-secret");
    DbKey createdKey = repository.newKey(createTx, userId, initialJson);
    createTx.commit();

    long keyId = createdKey.entity.getKey().getId();
    Key keyKey = KeyFactory.createKey("Key", keyId);

    // 2. Perform updateKey within a transaction and commit it.
    Transaction updateTx = ds.beginTransaction();
    JsonObject updatedJson = createKeyJson("Updated Key", "Updated Description", "updated-secret");
    repository.updateKey(updateTx, userId, keyId, updatedJson);
    updateTx.commit();

    // 3. Verify datastore holds updated values for both Key and KeyAcl.
    Entity keyEntity = ds.get(keyKey);
    assertThat(getEncryptedText(keyEntity, "name"))
        .isEqualTo(getEncryptedText(updatedJson, "name"));
    assertThat(getEncryptedText(keyEntity, "description"))
        .isEqualTo(getEncryptedText(updatedJson, "description"));

    Key aclKey = KeyFactory.createKey(keyKey, "KeyAcl", userId.asString());
    Entity aclEntity = ds.get(aclKey);
    @SuppressWarnings("unchecked")
    List<Text> acls = (List<Text>) aclEntity.getProperty("encryptions");
    assertThat(acls).hasSize(1);
    assertThat(acls.get(0).getValue())
        .isEqualTo(getEncryptedText(updatedJson.getAsJsonArray("encryptions").get(0).getAsJsonObject()));
  }

  @Test
  public void updateKey_executesPutsWithinProvidedTransaction() {
    UserId userId = UserId.fromString("user-1");

    Transaction createTx = ds.beginTransaction();
    JsonObject initialJson = createKeyJson("Original Key", "Original Description", "original-secret");
    DbKey createdKey = repository.newKey(createTx, userId, initialJson);
    createTx.commit();

    long keyId = createdKey.entity.getKey().getId();

    List<Transaction> putTransactions = new ArrayList<>();
    int[] nonTransactionalPuts = new int[]{0};

    DatastoreService trackingDs = (DatastoreService) Proxy.newProxyInstance(
        DatastoreService.class.getClassLoader(),
        new Class<?>[]{DatastoreService.class},
        (proxy, method, args) -> {
          if (method.getName().equals("put")) {
            if (args != null && args.length >= 2 && args[0] instanceof Transaction) {
              putTransactions.add((Transaction) args[0]);
            } else {
              nonTransactionalPuts[0]++;
            }
          }
          return method.invoke(ds, args);
        });

    KeyRepository trackingRepo = new KeyRepository(trackingDs);

    Transaction updateTx = ds.beginTransaction();
    JsonObject updatedJson = createKeyJson("Updated Key", "Updated Description", "updated-secret");
    trackingRepo.updateKey(updateTx, userId, keyId, updatedJson);
    updateTx.commit();

    // Both Key and KeyAcl puts must have passed the exact updateTx transaction.
    assertThat(putTransactions).containsExactly(updateTx, updateTx);
    assertThat(nonTransactionalPuts[0]).isEqualTo(0);
  }

  @Test
  public void updateKey_onlyUpdatesAclForSpecifiedUser() throws Exception {
    UserId user1 = UserId.fromString("user-1");
    UserId user2 = UserId.fromString("user-2");

    Transaction createTx = ds.beginTransaction();
    JsonObject initialJson = createKeyJson("Key 1", "Desc 1", "secret-1");
    DbKey createdKey = repository.newKey(createTx, user1, initialJson);

    // Add a second user ACL
    DbKeyAcl user2Acl = DbKeyAcl.newAcl(
        createdKey,
        user2,
        List.of(dummyEncryptedValue("secret-2")));
    ds.put(createTx, user2Acl.entity);
    createTx.commit();

    long keyId = createdKey.entity.getKey().getId();
    Key keyKey = KeyFactory.createKey("Key", keyId);

    // Update key as user1
    Transaction updateTx = ds.beginTransaction();
    JsonObject updatedJson = createKeyJson("Key 1 Updated", "Desc 1 Updated", "secret-1-updated");
    repository.updateKey(updateTx, user1, keyId, updatedJson);
    updateTx.commit();

    // Verify user1's ACL was updated
    Key user1AclKey = KeyFactory.createKey(keyKey, "KeyAcl", user1.asString());
    Entity user1AclEntity = ds.get(user1AclKey);
    @SuppressWarnings("unchecked")
    List<Text> user1Acls = (List<Text>) user1AclEntity.getProperty("encryptions");
    assertThat(user1Acls.get(0).getValue())
        .isEqualTo(getEncryptedText(updatedJson.getAsJsonArray("encryptions").get(0).getAsJsonObject()));

    // Verify user2's ACL was NOT touched
    Key user2AclKey = KeyFactory.createKey(keyKey, "KeyAcl", user2.asString());
    Entity user2AclEntity = ds.get(user2AclKey);
    @SuppressWarnings("unchecked")
    List<Text> user2Acls = (List<Text>) user2AclEntity.getProperty("encryptions");
    assertThat(user2Acls.get(0).getValue())
        .isEqualTo(dummyEncryptedValue("secret-2").toText().getValue());
  }

  @Test
  public void updateKey_nonExistentKeyThrowsPermissionDenied() {
    UserId userId = UserId.fromString("user-1");
    Transaction tx = ds.beginTransaction();
    try {
      JsonObject json = createKeyJson("Key", "Desc", "secret");
      assertThrows(
          PermissionDeniedException.class,
          () -> repository.updateKey(tx, userId, 999999L, json));
    } finally {
      tx.rollback();
    }
  }

  private static JsonObject createKeyJson(String name, String description, String encryptionData) {
    JsonObject json = new JsonObject();
    json.add("name", dummyEncryptedValue(name).toJsonObject());
    json.add("description", dummyEncryptedValue(description).toJsonObject());
    JsonArray encryptions = new JsonArray();
    encryptions.add(dummyEncryptedValue(encryptionData).toJsonObject());
    json.add("encryptions", encryptions);
    return json;
  }

  private static EncryptedValue dummyEncryptedValue(String content) {
    byte[] iv = new byte[16];
    byte[] ciphertext = content.getBytes(StandardCharsets.UTF_8);
    byte[] signature = new byte[32];
    return new EncryptedValue(EncryptionAlgorithm.AES_256_CBC_HMAC_SHA256, iv, ciphertext, signature);
  }

  private static String getEncryptedText(Entity entity, String property) {
    Text text = (Text) entity.getProperty(property);
    return text.getValue();
  }

  private static String getEncryptedText(JsonObject root, String memberName) {
    return getEncryptedText(root.getAsJsonObject(memberName));
  }

  private static String getEncryptedText(JsonObject encryptedValueJson) {
    return EncryptedValue.fromJsonObject(encryptedValueJson).toText().getValue();
  }
}
