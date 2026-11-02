#!/usr/bin/env python3

# Copyright 2012 Patrick Moor <patrick@moor.ws>
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

import hashlib
import hmac
import json
import os
import unittest

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

import crypto


class HmacTest(unittest.TestCase):

  def _runTest(self, key_hex, data_hex, expected_hash_hex):
    result = hmac.new(
        bytes.fromhex(key_hex), bytes.fromhex(data_hex), hashlib.sha256).hexdigest()
    self.assertEqual(expected_hash_hex, result)

  def test_one(self):
    self._runTest(
        "0b" * 20,
        "4869205468657265",
        "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")

  def test_two(self):
    self._runTest(
        "4a656665",
        "7768617420646f2079612077616e7420666f72206e6f7468696e673f",
        "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")

  def test_three(self):
    self._runTest(
        "aa" * 20,
        "dd" * 50,
        "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe")

  def test_four(self):
    self._runTest(
        "0102030405060708090a0b0c0d0e0f10111213141516171819",
        "cd" * 50,
        "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b")

  def test_five(self):
    self._runTest(
        "aa" * 131,
        "54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a65204b6579202d2048617368204b6579204669727374",
        "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54")


class AesTest(unittest.TestCase):

  def _runTest(self, key_hex, iv_hex, plaintext_hex, ciphertext_hex):
    cipher = Cipher(
        algorithms.AES(bytes.fromhex(key_hex)),
        modes.CBC(bytes.fromhex(iv_hex)))
    encryptor = cipher.encryptor()
    c = encryptor.update(bytes.fromhex(plaintext_hex)) + encryptor.finalize()
    self.assertEqual(ciphertext_hex, c.hex())

    decryptor = cipher.decryptor()
    new_plaintext = decryptor.update(c) + decryptor.finalize()
    self.assertEqual(plaintext_hex, new_plaintext.hex())

  def test_one(self):
    self._runTest(
        "8000000000000000000000000000000000000000000000000000000000000000",
        "00000000000000000000000000000000",
        "00000000000000000000000000000000",
        "e35a6dcb19b201a01ebcfa8aa22b5759")

  def test_two(self):
    self._runTest(
        "fffffffffffffffffffffffffffffffffffffffffffffff80000000000000000",
        "00000000000000000000000000000000",
        "00000000000000000000000000000000",
        "6168b00ba7859e0970ecfd757efecf7c")

  def test_three(self):
    self._runTest(
        "0000000000000000000000000000000000000000000000000000000000000000",
        "00000000000000000000000000000000",
        "ffffff00000000000000000000000000",
        "ac86bc606b6640c309e782f232bf367f")

  def test_four(self):
    self._runTest(
        "fca02f3d5011cfc5c1e23165d413a049d4526a991827424d896fe3435e0bf68e",
        "00000000000000000000000000000000",
        "00000000000000000000000000000000",
        "179a49c712154bbffbe6e7a84a18e220")

  def test_five(self):
    self._runTest(
        "0000000000000000000000000000000000000000000000000000000000000000",
        "00000000000000000000000000000000",
        "8a560769d605868ad80d819bdba03771",
        "38f2c7ae10612415d27ca190d27da8b4")


class PBKDF2Test(unittest.TestCase):
  """based on http://www.ietf.org/rfc/rfc6070.txt"""

  def test_one(self):
    self.assertEqual(
        "0c60c80f961f0e71f3a9b524af6012062fe037a6",
        hashlib.pbkdf2_hmac("sha1", b"password", b"salt", 1, 20).hex())

  def test_two(self):
    self.assertEqual(
        "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957",
        hashlib.pbkdf2_hmac("sha1", b"password", b"salt", 2, 20).hex())

  def test_three(self):
    self.assertEqual(
        "4b007901b765489abead49d926f721d065a429c1",
        hashlib.pbkdf2_hmac("sha1", b"password", b"salt", 4096, 20).hex())

  def test_five(self):
    self.assertEqual(
        "3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038",
        hashlib.pbkdf2_hmac(
            "sha1",
            b"passwordPASSWORDpassword",
            b"saltSALTsaltSALTsaltSALTsaltSALTsalt",
            4096,
            25).hex())

  def test_six(self):
    self.assertEqual(
        "56fa6aa75548099dcc37d7f03425e0c3",
        hashlib.pbkdf2_hmac("sha1", b"pass\0word", b"sa\0lt", 4096, 16).hex())


class LegacyDataTest(unittest.TestCase):

  def test_reads_legacy_client_data(self):
    resource_path = os.path.join(
        os.path.dirname(__file__), "..", "src", "test", "resources", "legacy-client-data.json")
    with open(resource_path, "r", encoding="utf-8") as f:
      legacy_data = json.load(f)

    for expected_key in legacy_data["expected"]:
      key_name = expected_key["name"]
      passphrases = expected_key["passphrases"]

      # Find matching key in "keys"
      matched = False
      for key_entry in legacy_data["keys"]:
        for passphrase in passphrases:
          secret_key = crypto.extractSecretKey(key_entry, passphrase)
          if secret_key is None:
            continue
          matched = True
          self.assertEqual(key_name, crypto.decryptSecret(key_entry["name"], secret_key))
          self.assertEqual(
              expected_key["description"],
              crypto.decryptSecret(key_entry["description"], secret_key))

          expected_secrets = {
              s["name"]: {
                  "description": s["description"],
                  "properties": {p["name"]: p["value"] for p in s["properties"]}
              }
              for s in expected_key["secrets"]
          }

          actual_secrets = {}
          for act_sec in key_entry["secrets"]:
            sec_name = crypto.decryptSecret(act_sec["name"], secret_key)
            sec_desc = crypto.decryptSecret(act_sec["description"], secret_key)
            sec_props = {
                crypto.decryptSecret(p["name"], secret_key):
                    crypto.decryptSecret(p["value"], secret_key)
                for p in act_sec["properties"]
            }
            actual_secrets[sec_name] = {
                "description": sec_desc,
                "properties": sec_props,
            }

          self.assertEqual(expected_secrets, actual_secrets)

      self.assertTrue(matched, f"Key {key_name} could not be unlocked")


class RoundTripTest(unittest.TestCase):

  def test_wrap_and_encrypt(self):
    secret_key = crypto.newRandomSecretKey()
    self.assertEqual(32, len(secret_key))

    passphrase = "correct horse battery staple 🔑"
    wrapped = crypto.createEncryptionWithPassphrase(secret_key, passphrase)
    self.assertEqual(crypto.PASSPHRASE_ALGORITHM, wrapped["algorithm"])
    key_resource = {"encryptions": [wrapped]}

    extracted = crypto.extractSecretKey(key_resource, passphrase)
    self.assertEqual(secret_key, extracted)
    self.assertIsNone(crypto.extractSecretKey(key_resource, "wrong-passphrase"))

    enc_val = crypto.createEncryption(secret_key, "Secret Message with Unicode: 🚀🔒")
    dec_val = crypto.decryptSecret(enc_val, secret_key)
    self.assertEqual("Secret Message with Unicode: 🚀🔒", dec_val)


class BrowserClientDataTest(unittest.TestCase):
  """A key's raw secret wrapped by the browser client (crypto.js) with the current algorithm."""

  PASSPHRASE = 'zweites Passwort ä 🔑'
  RAW_SECRET = bytes.fromhex("00070e151c232a31383f464d545b626970777e858c939aa1a8afb6bdc4cbd2d9")
  ENCRYPTION = {
    "version": 0,
    "algorithm": "PBKDF2_SHA512_210000_AES_256_CBC_HMAC_SHA256",
    "iv": "7aVNClbJ8UW5oC/JfwreHw==",
    "ciphertext": "YMpFKl5YbOduSBqm0svutQVGOftITHjtTjDh2HPSgmnVzf9gdbEadKn2t3TtrTyL",
    "signature": "VJwuTVlOVmNtxIG5w4ET7wJx97Pf2ilW8CqSSBhCxQU=",
  }
  VALUE = {
    "version": 0,
    "algorithm": "AES_256_CBC_HMAC_SHA256",
    "iv": "UcWfTNqPk1379nMkR2K2GA==",
    "ciphertext": "mY7DFyxj+m6yB/OuWnAstCeMf9gbOzTp+o4PAreowBQ=",
    "signature": "PBgjR+xQVFS7aYr3eQcXix/cTWS1zM+F1enaq6iTHm4=",
  }

  def test_unwraps_current_algorithm(self):
    key_resource = {"encryptions": [self.ENCRYPTION]}
    self.assertEqual(self.RAW_SECRET, crypto.extractSecretKey(key_resource, self.PASSPHRASE))
    self.assertIsNone(crypto.extractSecretKey(key_resource, "wrong-passphrase"))
    self.assertEqual("written by crypto.js", crypto.decryptSecret(self.VALUE, self.RAW_SECRET))

  def test_skips_unknown_algorithms(self):
    unknown = dict(self.ENCRYPTION, algorithm="SOMETHING_NEW")
    key_resource = {"encryptions": [unknown, self.ENCRYPTION]}
    self.assertEqual(self.RAW_SECRET, crypto.extractSecretKey(key_resource, self.PASSPHRASE))


if __name__ == '__main__':
  unittest.main()
