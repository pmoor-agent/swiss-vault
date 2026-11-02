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

import base64
import hashlib
import hmac
import secrets
from typing import Any, Dict, Optional, Union

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

__author__ = 'pmoor'

VALUE_ALGORITHM = "AES_256_CBC_HMAC_SHA256"
# written for new passphrases
PASSPHRASE_ALGORITHM = "PBKDF2_SHA512_210000_AES_256_CBC_HMAC_SHA256"
# written until 2026, still read
LEGACY_PASSPHRASE_ALGORITHM = "PBKDF2_SHA1_AES_256_CBC_HMAC_SHA256"

# PBKDF2 hash and iterations per passphrase algorithm
PASSPHRASE_KEY_DERIVATIONS = {
  PASSPHRASE_ALGORITHM: ("sha512", 210000),
  LEGACY_PASSPHRASE_ALGORITHM: ("sha1", 1000),
}


def _derivePassphraseKey(passphrase: str, salt: bytes, algorithm: str) -> bytes:
  hash_name, iterations = PASSPHRASE_KEY_DERIVATIONS[algorithm]
  return hashlib.pbkdf2_hmac(hash_name, passphrase.encode('utf-8'), salt, iterations, 32)


def _pad(data: bytes) -> bytes:
  padder = padding.PKCS7(128).padder()
  return padder.update(data) + padder.finalize()


def _unpad(data: bytes) -> bytes:
  unpadder = padding.PKCS7(128).unpadder()
  return unpadder.update(data) + unpadder.finalize()


def newRandomSecretKey() -> bytes:
  return secrets.token_bytes(32)


def createEncryption(secret_key: bytes, value: Union[str, bytes]) -> Dict[str, Any]:
  if isinstance(value, str):
    cleartext = value.encode('utf-8')
  else:
    cleartext = value

  iv = secrets.token_bytes(16)
  cipher = Cipher(algorithms.AES(secret_key), modes.CBC(iv))
  encryptor = cipher.encryptor()
  ciphertext = encryptor.update(_pad(cleartext)) + encryptor.finalize()

  signature = hmac.new(secret_key, iv + cleartext, hashlib.sha256).digest()

  return {
    "version": 0,
    "algorithm": VALUE_ALGORITHM,
    "iv": base64.b64encode(iv).decode("ascii"),
    "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
    "signature": base64.b64encode(signature).decode("ascii"),
  }


def createEncryptionWithPassphrase(secret_key: bytes, passphrase: str) -> Dict[str, Any]:
  iv_and_salt = secrets.token_bytes(16)
  password_derived_key = _derivePassphraseKey(passphrase, iv_and_salt, PASSPHRASE_ALGORITHM)

  cipher = Cipher(algorithms.AES(password_derived_key), modes.CBC(iv_and_salt))
  encryptor = cipher.encryptor()
  encrypted_key = encryptor.update(_pad(secret_key)) + encryptor.finalize()

  signature = hmac.new(password_derived_key, iv_and_salt + secret_key, hashlib.sha256).digest()

  return {
    "version": 0,
    "algorithm": PASSPHRASE_ALGORITHM,
    "iv": base64.b64encode(iv_and_salt).decode("ascii"),
    "ciphertext": base64.b64encode(encrypted_key).decode("ascii"),
    "signature": base64.b64encode(signature).decode("ascii"),
  }


def extractSecretKey(key_resource: Dict[str, Any], passphrase: str) -> Optional[bytes]:
  for encryption in key_resource.get("encryptions", []):
    algorithm = encryption.get("algorithm")
    if algorithm not in PASSPHRASE_KEY_DERIVATIONS:
      continue

    iv = base64.b64decode(encryption["iv"])
    ciphertext = base64.b64decode(encryption["ciphertext"])
    signature = base64.b64decode(encryption["signature"])

    password_derived_key = _derivePassphraseKey(passphrase, iv, algorithm)

    try:
      cipher = Cipher(algorithms.AES(password_derived_key), modes.CBC(iv))
      decryptor = cipher.decryptor()
      secret_key = _unpad(decryptor.update(ciphertext) + decryptor.finalize())
    except Exception:
      # wrong key or invalid padding; try other encryptions
      continue

    expected_signature = hmac.new(password_derived_key, iv + secret_key, hashlib.sha256).digest()
    if hmac.compare_digest(expected_signature, signature):
      return secret_key

  return None


def decryptSecret(encryption: Dict[str, Any], secret_key: bytes) -> str:
  if encryption.get("algorithm") != VALUE_ALGORITHM:
    raise ValueError(f"unsupported algorithm: {encryption.get('algorithm')}")

  iv = base64.b64decode(encryption["iv"])
  ciphertext = base64.b64decode(encryption["ciphertext"])
  signature = base64.b64decode(encryption["signature"])

  cipher = Cipher(algorithms.AES(secret_key), modes.CBC(iv))
  decryptor = cipher.decryptor()
  try:
    cleartext = _unpad(decryptor.update(ciphertext) + decryptor.finalize())
  except Exception as e:
    raise ValueError("decryption failed; invalid key or corrupted data") from e

  expected_signature = hmac.new(secret_key, iv + cleartext, hashlib.sha256).digest()
  if not hmac.compare_digest(expected_signature, signature):
    raise ValueError("invalid signature")

  return cleartext.decode('utf-8')
