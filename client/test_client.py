#!/usr/bin/env python3

# Copyright 2026 Patrick Moor <patrick@moor.ws>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import base64
import http.client
import os
import secrets
import sys
import unittest
import urllib.parse
import uuid

import client
import crypto


class ClientDevTest(unittest.TestCase):

  @classmethod
  def setUpClass(cls):
    cls.server_url = sys.argv[1] if len(sys.argv) > 1 and not sys.argv[1].startswith("-") else "http://localhost:8181"
    # Check if server is accessible
    parsed = urllib.parse.urlparse(cls.server_url)
    cls.server_available = False
    try:
      conn = http.client.HTTPConnection(parsed.netloc, timeout=2)
      conn.request("GET", "/favicon.ico")
      resp = conn.getresponse()
      if resp.status in (200, 404):
        cls.server_available = True
      conn.close()
    except Exception:
      pass

  def test_cookie_generation_and_storage(self):
    user_id = f"test-{uuid.uuid4()}"
    cookie = client.make_dev_cookie(user_id)
    self.assertTrue(cookie.startswith(f"{user_id}:"))
    parts = cookie.split(":")
    self.assertEqual(3, len(parts))

    test_server = "http://localhost:9999"
    client.save_cached_cookie(test_server, cookie)
    loaded = client.load_cached_cookie(test_server)
    self.assertEqual(cookie, loaded)

    client.clear_cached_cookie(test_server)
    self.assertIsNone(client.load_cached_cookie(test_server))

  def test_value_encryption_aes_gcm_and_legacy_cbc(self):
    secret_key = crypto.newRandomSecretKey()

    # 1. createEncryption writes AES_256_GCM
    enc = crypto.createEncryption(secret_key, "Secret value with unicode 🔑")
    self.assertEqual("AES_256_GCM", enc["algorithm"])
    self.assertEqual(0, enc["version"])
    self.assertEqual(12, len(base64.b64decode(enc["iv"])))
    self.assertEqual(16, len(base64.b64decode(enc["signature"])))
    self.assertEqual("Secret value with unicode 🔑", crypto.decryptSecret(enc, secret_key))

    # 2. createEncryption with empty string ""
    enc_empty = crypto.createEncryption(secret_key, "")
    self.assertEqual("AES_256_GCM", enc_empty["algorithm"])
    self.assertEqual("", enc_empty["ciphertext"])
    self.assertEqual(0, len(base64.b64decode(enc_empty["ciphertext"])))
    self.assertEqual(16, len(base64.b64decode(enc_empty["signature"])))
    self.assertEqual("", crypto.decryptSecret(enc_empty, secret_key))

    # 3. Decrypt legacy AES_256_CBC_HMAC_SHA256 value
    import hashlib
    import hmac
    from cryptography.hazmat.primitives import padding
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    iv = secrets.token_bytes(16)
    cleartext = "Legacy secret data".encode("utf-8")
    padder = padding.PKCS7(128).padder()
    padded = padder.update(cleartext) + padder.finalize()
    cipher = Cipher(algorithms.AES(secret_key), modes.CBC(iv))
    enc_legacy = cipher.encryptor()
    ciphertext = enc_legacy.update(padded) + enc_legacy.finalize()
    signature = hmac.new(secret_key, iv + cleartext, hashlib.sha256).digest()
    legacy_encryption = {
      "version": 0,
      "algorithm": "AES_256_CBC_HMAC_SHA256",
      "iv": base64.b64encode(iv).decode("ascii"),
      "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
      "signature": base64.b64encode(signature).decode("ascii"),
    }
    self.assertEqual("Legacy secret data", crypto.decryptSecret(legacy_encryption, secret_key))

    # 4. Error conditions
    bad_enc = dict(enc, signature=base64.b64encode(b"0" * 16).decode("ascii"))
    with self.assertRaises(ValueError):
      crypto.decryptSecret(bad_enc, secret_key)

    unknown_algo = dict(enc, algorithm="UNKNOWN_ALGO")
    with self.assertRaises(ValueError):
      crypto.decryptSecret(unknown_algo, secret_key)

  def test_vault_lifecycle(self):
    if not self.server_available:
      self.skipTest(f"Dev server not accessible at {self.server_url}")

    user_id = f"test-{uuid.uuid4()}"
    conn = client.AuthenticatedConnection(
        server_url=self.server_url, dev_user=user_id)

    # 1. Initially no keys
    keys = client.getKeys(conn)
    self.assertEqual(0, len(keys))

    # 2. Create a key
    passphrase = "test-passphrase-🔑"
    created_key = client.createNewKey(conn, passphrase, "My Vault", "Work & Personal")
    key_id = str(created_key["id"])

    # 3. List and get key
    keys = client.getKeys(conn)
    self.assertEqual(1, len(keys))
    self.assertEqual(key_id, str(keys[0]["id"]))

    key = client.getKey(conn, key_id)
    secret_key = crypto.extractSecretKey(key, passphrase)
    self.assertIsNotNone(secret_key)
    self.assertEqual("My Vault", crypto.decryptSecret(key["name"], secret_key))
    self.assertEqual("Work & Personal", crypto.decryptSecret(key["description"], secret_key))

    # 4. Create secrets under key
    sec1 = client.createNewSecret(conn, key_id, secret_key, "Email Login", "Personal email")
    sec1_id = str(sec1["id"])

    sec2 = client.createNewSecret(conn, key_id, secret_key, "Bank PIN", "Checking account")
    sec2_id = str(sec2["id"])

    secrets_list = client.getSecrets(conn, key_id)
    self.assertEqual(2, len(secrets_list))

    # 5. Create properties under secret 1
    p1 = client.createNewSecretProperty(conn, key_id, sec1_id, secret_key, "username", "alice@example.com")
    p1_id = str(p1["id"])
    p2 = client.createNewSecretProperty(conn, key_id, sec1_id, secret_key, "password", "hunter2-äöü")
    p2_id = str(p2["id"])

    props = client.getSecretProperties(conn, key_id, sec1_id)
    self.assertEqual(2, len(props))
    decrypted_props = {
        crypto.decryptSecret(p["name"], secret_key): crypto.decryptSecret(p["value"], secret_key)
        for p in props
    }
    self.assertEqual({"username": "alice@example.com", "password": "hunter2-äöü"}, decrypted_props)

    # 6. Update property
    client.updateSecretProperty(conn, key_id, sec1_id, p2_id, secret_key, "password", "new-hunter3-🔒")
    props = client.getSecretProperties(conn, key_id, sec1_id)
    decrypted_props = {
        crypto.decryptSecret(p["name"], secret_key): crypto.decryptSecret(p["value"], secret_key)
        for p in props
    }
    self.assertEqual({"username": "alice@example.com", "password": "new-hunter3-🔒"}, decrypted_props)

    # 7. Delete property
    client.deleteSecretProperty(conn, key_id, sec1_id, p1_id)
    props = client.getSecretProperties(conn, key_id, sec1_id)
    self.assertEqual(1, len(props))

    # 8. Export data & Dump
    exported = client.exportData(conn, passphrase)
    self.assertEqual(2, len(exported))
    email_sec = next(s for s in exported if s["name"] == "Email Login")
    self.assertEqual("Personal email", email_sec["description"])
    self.assertEqual([{"name": "password", "value": "new-hunter3-🔒"}], email_sec["properties"])

    client.dumpAllData(conn, passphrase)

    # 9. Delete secrets and key
    client.deleteSecret(conn, key_id, sec1_id)
    client.deleteSecret(conn, key_id, sec2_id)
    self.assertEqual(0, len(client.getSecrets(conn, key_id)))

    client.deleteKey(conn, key_id)
    self.assertEqual(0, len(client.getKeys(conn)))

    conn.close()

  def test_cli_login_endpoints(self):
    if not self.server_available:
      self.skipTest(f"Dev server not accessible at {self.server_url}")

    parsed = urllib.parse.urlparse(self.server_url)
    conn = http.client.HTTPConnection(parsed.netloc)

    # Unauthenticated GET /cli-login redirects to Google OAuth
    conn.request("GET", "/cli-login")
    resp = conn.getresponse()
    self.assertEqual(302, resp.status)
    loc = resp.getheader("Location")
    self.assertIn("accounts.google.com/o/oauth2/auth", loc)
    self.assertIn("state=CLI_LOGIN:", loc)
    self.assertEqual("no-store", resp.getheader("Cache-Control"))
    self.assertEqual("max-age=7776000; includeSubDomains", resp.getheader("Strict-Transport-Security"))
    self.assertEqual("nosniff", resp.getheader("X-Content-Type-Options"))
    csp_redirect = resp.getheader("Content-Security-Policy")
    self.assertIsNotNone(csp_redirect)
    self.assertIn("frame-ancestors 'none'", csp_redirect)
    set_cookie = resp.getheader("Set-Cookie")
    self.assertIsNotNone(set_cookie)
    self.assertIn("oauth_state=CLI_LOGIN:", set_cookie)
    self.assertIn("Path=/", set_cookie)
    self.assertIn("SameSite=Lax", set_cookie)
    resp.read()

    # OAuth callback rejects request with missing cookie
    conn.request("GET", "/oauth2callback?code=fake_code&state=CLI_LOGIN:1234567890abcdef1234567890abcdef")
    resp = conn.getresponse()
    self.assertEqual(400, resp.status)
    resp.read()

    # OAuth callback rejects request with mismatched cookie
    conn.request("GET", "/oauth2callback?code=fake_code&state=CLI_LOGIN:1234567890abcdef1234567890abcdef",
                 headers={"Cookie": "oauth_state=CLI_LOGIN:differentnonce1234567890abcdef"})
    resp = conn.getresponse()
    self.assertEqual(400, resp.status)
    resp.read()

    # OAuth callback rejects legacy static state without nonce
    conn.request("GET", "/oauth2callback?code=attacker_code&state=HOME",
                 headers={"Cookie": "oauth_state=HOME"})
    resp = conn.getresponse()
    self.assertEqual(400, resp.status)
    resp.read()

    # Authenticated GET /cli-login shows HTML with auth token in textarea
    user_id = f"test-{uuid.uuid4()}"
    auth_cookie = client.make_dev_cookie(user_id)
    conn.request("GET", "/cli-login", headers={"Cookie": f"auth={auth_cookie}"})
    resp = conn.getresponse()
    self.assertEqual(200, resp.status)
    self.assertEqual("no-store", resp.getheader("Cache-Control"))
    self.assertEqual("max-age=7776000; includeSubDomains", resp.getheader("Strict-Transport-Security"))
    self.assertEqual("nosniff", resp.getheader("X-Content-Type-Options"))
    csp = resp.getheader("Content-Security-Policy")
    self.assertIsNotNone(csp)
    self.assertIn("frame-ancestors 'none'", csp)
    self.assertIn("default-src 'none'", csp)
    self.assertIn("base-uri 'none'", csp)
    self.assertIn("form-action 'none'", csp)
    self.assertIn("style-src 'self'", csp)
    self.assertNotIn("'unsafe-inline'", csp)
    body = resp.read().decode("utf-8")
    self.assertIn("CLI Authentication Token", body)
    self.assertIn(user_id, body)
    # The textarea contains a freshly generated auth cookie for user_id
    self.assertIn(f">{user_id}:", body)
    self.assertIn("Expires:", body)
    self.assertIn("minutes)", body)
    self.assertNotIn("onclick", body)
    self.assertNotIn("<style", body)
    self.assertNotIn("<link", body)
    self.assertIn('<textarea readonly rows="4" cols="80">', body)

    conn.close()


if __name__ == '__main__':
  unittest.main(argv=[sys.argv[0]])
