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
package ws.moor.swissvault.persistence;

import com.google.appengine.api.datastore.*;
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
import ws.moor.swissvault.persistence.model.DbKey;
import ws.moor.swissvault.persistence.model.DbSecret;
import ws.moor.swissvault.persistence.model.DbSecretProperty;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.fail;

public class CascadeDeleteTest {

  private final LocalServiceTestHelper helper =
      new LocalServiceTestHelper(new LocalDatastoreServiceTestConfig().setApplyAllHighRepJobPolicy());

  private DatastoreService ds;
  private KeyRepository keyRepository;
  private SecretRepository secretRepository;

  @Before
  public void setUp() {
    helper.setUp();
    ds = DatastoreServiceFactory.getDatastoreService();
    keyRepository = new KeyRepository(ds);
    secretRepository = new SecretRepository(ds);
  }

  @After
  public void tearDown() {
    helper.tearDown();
  }

  @Test
  public void testDeleteKeyCascadesToAllDescendants() {
    UserId user1 = UserId.fromString("user-1");
    UserId user2 = UserId.fromString("user-2");

    // 1. Create Key 1 with secrets and properties
    Transaction tx1 = ds.beginTransaction();
    DbKey key1 = keyRepository.newKey(tx1, user1, createKeyJson("Key 1"));
    tx1.commit();
    long key1Id = key1.entity.getKey().getId();
    Key key1Key = key1.entity.getKey();

    Transaction txSecret1 = ds.beginTransaction();
    DbSecret secret1A = secretRepository.newSecret(txSecret1, key1Id, createSecretJson("Secret 1A"));
    DbSecret secret1B = secretRepository.newSecret(txSecret1, key1Id, createSecretJson("Secret 1B"));
    txSecret1.commit();
    long secret1AId = secret1A.entity.getKey().getId();
    long secret1BId = secret1B.entity.getKey().getId();

    Transaction txProp1 = ds.beginTransaction();
    DbSecretProperty prop1A1 = secretRepository.newSecretProperty(txProp1, secret1A, createPropertyJson("user", "alice"));
    DbSecretProperty prop1A2 = secretRepository.newSecretProperty(txProp1, secret1A, createPropertyJson("pass", "secret123"));
    DbSecretProperty prop1B1 = secretRepository.newSecretProperty(txProp1, secret1B, createPropertyJson("token", "xyz987"));
    txProp1.commit();

    // 2. Create Key 2 with secret and property (unrelated key to ensure isolation)
    Transaction tx2 = ds.beginTransaction();
    DbKey key2 = keyRepository.newKey(tx2, user2, createKeyJson("Key 2"));
    tx2.commit();
    long key2Id = key2.entity.getKey().getId();
    Key key2Key = key2.entity.getKey();

    Transaction txSecret2 = ds.beginTransaction();
    DbSecret secret2 = secretRepository.newSecret(txSecret2, key2Id, createSecretJson("Secret 2"));
    txSecret2.commit();

    Transaction txProp2 = ds.beginTransaction();
    DbSecretProperty prop2 = secretRepository.newSecretProperty(txProp2, secret2, createPropertyJson("key2prop", "val2"));
    txProp2.commit();

    // 3. Verify all entities exist under Key 1 prior to deletion
    assertThat(countEntitiesUnderAncestor(key1Key)).isEqualTo(7); // Key + KeyAcl + 2 Secrets + 3 SecretProperties
    assertThat(countEntitiesUnderAncestor(key2Key)).isEqualTo(4); // Key + KeyAcl + 1 Secret + 1 SecretProperty

    // 4. Delete Key 1
    Transaction txDel = ds.beginTransaction();
    keyRepository.delete(txDel, key1Id);
    txDel.commit();

    // 5. Verify NO entities remain under Key 1 ancestor
    assertThat(countEntitiesUnderAncestor(key1Key)).isEqualTo(0);

    // Verify specifically that kind queries under key1Key return empty lists
    assertThat(getKeysByKindAndAncestor("Key", key1Key)).isEmpty();
    assertThat(getKeysByKindAndAncestor("KeyAcl", key1Key)).isEmpty();
    assertThat(getKeysByKindAndAncestor("Secret", key1Key)).isEmpty();
    assertThat(getKeysByKindAndAncestor("SecretProperty", key1Key)).isEmpty();

    // Verify ds.get throws EntityNotFoundException for Key 1
    try {
      ds.get(key1Key);
      fail("Key 1 entity should have been deleted");
    } catch (EntityNotFoundException expected) {
      // expected
    }

    // Verify ds.get throws EntityNotFoundException for secrets under Key 1
    try {
      ds.get(secret1A.entity.getKey());
      fail("Secret 1A should have been deleted");
    } catch (EntityNotFoundException expected) {
      // expected
    }
    try {
      ds.get(secret1B.entity.getKey());
      fail("Secret 1B should have been deleted");
    } catch (EntityNotFoundException expected) {
      // expected
    }

    // Verify ds.get throws EntityNotFoundException for properties under Key 1
    try {
      ds.get(prop1A1.entity.getKey());
      fail("Property 1A1 should have been deleted");
    } catch (EntityNotFoundException expected) {
      // expected
    }

    // 6. Verify Key 2 and its descendants are completely unaffected
    assertThat(countEntitiesUnderAncestor(key2Key)).isEqualTo(4);
    assertThat(secretRepository.listSecrets(null, key2Id)).hasSize(1);
    assertThat(secretRepository.listSecretProperties(null, key2Id, secret2.entity.getKey().getId())).hasSize(1);
  }

  @Test
  public void testDeleteSecretCascadesToAllProperties() {
    UserId user = UserId.fromString("user-1");

    // 1. Create Key with two secrets
    Transaction tx = ds.beginTransaction();
    DbKey key = keyRepository.newKey(tx, user, createKeyJson("Key 1"));
    tx.commit();
    long keyId = key.entity.getKey().getId();

    Transaction txSecret = ds.beginTransaction();
    DbSecret secretA = secretRepository.newSecret(txSecret, keyId, createSecretJson("Secret A"));
    DbSecret secretB = secretRepository.newSecret(txSecret, keyId, createSecretJson("Secret B"));
    txSecret.commit();
    long secretAId = secretA.entity.getKey().getId();
    long secretBId = secretB.entity.getKey().getId();

    Transaction txProp = ds.beginTransaction();
    DbSecretProperty propA1 = secretRepository.newSecretProperty(txProp, secretA, createPropertyJson("propA1", "valA1"));
    DbSecretProperty propA2 = secretRepository.newSecretProperty(txProp, secretA, createPropertyJson("propA2", "valA2"));
    DbSecretProperty propB1 = secretRepository.newSecretProperty(txProp, secretB, createPropertyJson("propB1", "valB1"));
    txProp.commit();

    // Verify initial counts
    assertThat(secretRepository.listSecrets(null, keyId)).hasSize(2);
    assertThat(secretRepository.listSecretProperties(null, keyId, secretAId)).hasSize(2);
    assertThat(secretRepository.listSecretProperties(null, keyId, secretBId)).hasSize(1);

    // 2. Delete Secret A
    Transaction txDel = ds.beginTransaction();
    secretRepository.deleteSecret(txDel, keyId, secretAId);
    txDel.commit();

    // 3. Verify Secret A and its properties are gone
    try {
      secretRepository.getSecret(null, keyId, secretAId);
      fail("Secret A should have been deleted");
    } catch (EntityNotFoundException expected) {
      // expected
    }

    assertThat(secretRepository.listSecretProperties(null, keyId, secretAId)).isEmpty();
    assertThat(countEntitiesUnderAncestor(secretA.entity.getKey())).isEqualTo(0);

    // 4. Verify Secret B and Key are intact
    List<DbSecret> remainingSecrets = secretRepository.listSecrets(null, keyId);
    assertThat(remainingSecrets).hasSize(1);
    assertThat(remainingSecrets.get(0).entity.getKey().getId()).isEqualTo(secretBId);

    List<DbSecretProperty> remainingProps = secretRepository.listSecretProperties(null, keyId, secretBId);
    assertThat(remainingProps).hasSize(1);
    assertThat(remainingProps.get(0).entity.getKey().getId()).isEqualTo(propB1.entity.getKey().getId());
  }

  @Test
  public void testDeleteKeyWithNoSecretsOrProperties() {
    UserId user = UserId.fromString("user-empty");

    Transaction tx = ds.beginTransaction();
    DbKey key = keyRepository.newKey(tx, user, createKeyJson("Empty Key"));
    tx.commit();
    long keyId = key.entity.getKey().getId();
    Key keyKey = key.entity.getKey();

    assertThat(countEntitiesUnderAncestor(keyKey)).isEqualTo(2); // Key + KeyAcl

    Transaction txDel = ds.beginTransaction();
    keyRepository.delete(txDel, keyId);
    txDel.commit();

    assertThat(countEntitiesUnderAncestor(keyKey)).isEqualTo(0);
  }

  @Test
  public void testDeleteSecretWithNoProperties() {
    UserId user = UserId.fromString("user-empty-secret");

    Transaction tx = ds.beginTransaction();
    DbKey key = keyRepository.newKey(tx, user, createKeyJson("Key"));
    tx.commit();
    long keyId = key.entity.getKey().getId();

    Transaction txSecret = ds.beginTransaction();
    DbSecret secret = secretRepository.newSecret(txSecret, keyId, createSecretJson("Empty Secret"));
    txSecret.commit();
    long secretId = secret.entity.getKey().getId();

    assertThat(secretRepository.listSecrets(null, keyId)).hasSize(1);

    Transaction txDel = ds.beginTransaction();
    secretRepository.deleteSecret(txDel, keyId, secretId);
    txDel.commit();

    assertThat(secretRepository.listSecrets(null, keyId)).isEmpty();
    assertThat(countEntitiesUnderAncestor(secret.entity.getKey())).isEqualTo(0);
  }

  private int countEntitiesUnderAncestor(Key ancestor) {
    Query q = new Query(ancestor);
    q.setKeysOnly();
    PreparedQuery pq = ds.prepare(q);
    int count = 0;
    for (Entity ignored : pq.asIterable()) {
      count++;
    }
    return count;
  }

  private List<Key> getKeysByKindAndAncestor(String kind, Key ancestor) {
    Query q = new Query(kind, ancestor);
    q.setKeysOnly();
    PreparedQuery pq = ds.prepare(q);
    List<Key> keys = new ArrayList<>();
    for (Entity entity : pq.asIterable()) {
      keys.add(entity.getKey());
    }
    return keys;
  }

  private JsonObject createKeyJson(String label) {
    JsonObject keyJson = new JsonObject();
    keyJson.add("name", dummyEncryptedValue(label).toJsonObject());
    keyJson.add("description", dummyEncryptedValue("desc:" + label).toJsonObject());
    JsonArray encryptions = new JsonArray();
    encryptions.add(dummyEncryptedValue("enc:" + label).toJsonObject());
    keyJson.add("encryptions", encryptions);
    return keyJson;
  }

  private JsonObject createSecretJson(String label) {
    JsonObject secretJson = new JsonObject();
    secretJson.add("name", dummyEncryptedValue(label).toJsonObject());
    secretJson.add("description", dummyEncryptedValue("desc:" + label).toJsonObject());
    return secretJson;
  }

  private JsonObject createPropertyJson(String name, String value) {
    JsonObject propJson = new JsonObject();
    propJson.add("name", dummyEncryptedValue(name).toJsonObject());
    propJson.add("value", dummyEncryptedValue(value).toJsonObject());
    return propJson;
  }

  private EncryptedValue dummyEncryptedValue(String label) {
    return new EncryptedValue(
        EncryptionAlgorithm.AES_256_CBC_HMAC_SHA256,
        new byte[16],
        label.getBytes(StandardCharsets.UTF_8),
        new byte[32]);
  }
}
