/*
  Copyright 2026 Patrick Moor <patrick@moor.ws>

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
*/

// All formats ever written stay readable.
//
// AES_256_CBC_HMAC_SHA256 (names, descriptions and values, using a key's 32 byte raw secret):
//   AES-256-CBC with PKCS#7 padding and a random 16 byte IV. The signature is HMAC-SHA256 over
//   iv || cleartext, using the same raw secret as HMAC key. Unchanged since 2012.
//
// PBKDF2_SHA512_210000_AES_256_CBC_HMAC_SHA256 (a key's raw secret, wrapped with a passphrase):
//   as above, keyed with PBKDF2-HMAC-SHA512(utf8(passphrase), salt = iv, 210000 iterations).
//   Written since 2026; 210000 iterations of SHA-512 is OWASP's recommendation for PBKDF2.
//
// PBKDF2_SHA1_AES_256_CBC_HMAC_SHA256 (legacy, a key's raw secret wrapped with a passphrase):
//   as above, keyed with PBKDF2-HMAC-SHA1(utf8(passphrase), salt = iv, 1000 iterations).
//   Written until 2026, still read.

/**
 * @typedef {object} EncryptedValue
 * @property {number} version always 0
 * @property {string} algorithm
 * @property {string} iv base64
 * @property {string} ciphertext base64
 * @property {string} signature base64
 */

const VALUE_ALGORITHM = 'AES_256_CBC_HMAC_SHA256';
const PASSPHRASE_ALGORITHM = 'PBKDF2_SHA512_210000_AES_256_CBC_HMAC_SHA256';
const LEGACY_PASSPHRASE_ALGORITHM = 'PBKDF2_SHA1_AES_256_CBC_HMAC_SHA256';

/** @type {Record<string, {hash: string, iterations: number} | undefined>} */
const PASSPHRASE_KEY_DERIVATIONS = {
  [PASSPHRASE_ALGORITHM]: {hash: 'SHA-512', iterations: 210_000},
  [LEGACY_PASSPHRASE_ALGORITHM]: {hash: 'SHA-1', iterations: 1000},
};

/** Thrown when a value cannot be decrypted with the given key: wrong key, or tampered data. */
export class DecryptionError extends Error {}

/** @returns {Uint8Array<ArrayBuffer>} a new random raw secret for a key */
export function newRawSecret() {
  return crypto.getRandomValues(new Uint8Array(32));
}

/**
 * @param {Uint8Array<ArrayBuffer>} rawSecret
 * @param {string} cleartext
 * @returns {Promise<EncryptedValue>}
 */
export function encrypt(rawSecret, cleartext) {
  return encryptBytes(rawSecret, new TextEncoder().encode(cleartext), VALUE_ALGORITHM, randomIv());
}

/**
 * @param {Uint8Array<ArrayBuffer>} rawSecret
 * @param {EncryptedValue} value
 * @returns {Promise<string>}
 */
export async function decrypt(rawSecret, value) {
  if (value.algorithm !== VALUE_ALGORITHM) {
    throw new Error('unsupported algorithm: ' + value.algorithm);
  }
  return new TextDecoder().decode(await decryptBytes(rawSecret, value));
}

/**
 * Wraps a key's raw secret with a passphrase.
 *
 * @param {string} passphrase
 * @param {Uint8Array<ArrayBuffer>} rawSecret
 * @returns {Promise<EncryptedValue>}
 */
export async function wrapSecret(passphrase, rawSecret) {
  const salt = randomIv();
  return encryptBytes(
      await derivePassphraseKey(passphrase, salt, PASSPHRASE_ALGORITHM), rawSecret, PASSPHRASE_ALGORITHM, salt);
}

/**
 * @param {EncryptedValue} value a key's raw secret, wrapped with a passphrase
 * @returns {boolean} whether it uses the weak legacy key derivation, and should be replaced
 */
export function isLegacyEncryption(value) {
  return value.algorithm === LEGACY_PASSPHRASE_ALGORITHM;
}

/**
 * @param {string} passphrase
 * @param {EncryptedValue} value
 * @returns {Promise<Uint8Array<ArrayBuffer> | null>} the raw secret, or null if the passphrase does not match
 */
export async function unwrapSecret(passphrase, value) {
  if (!PASSPHRASE_KEY_DERIVATIONS[value.algorithm]) {
    return null;
  }
  try {
    return await decryptBytes(await derivePassphraseKey(passphrase, fromBase64(value.iv), value.algorithm), value);
  } catch (e) {
    if (e instanceof DecryptionError) {
      return null;
    }
    throw e;
  }
}

/**
 * @param {string} passphrase
 * @param {Uint8Array<ArrayBuffer>} salt
 * @param {string} algorithm one of the passphrase algorithms
 */
async function derivePassphraseKey(passphrase, salt, algorithm) {
  const derivation = PASSPHRASE_KEY_DERIVATIONS[algorithm];
  if (!derivation) {
    throw new Error('unsupported algorithm: ' + algorithm);
  }
  let baseKey;
  try {
    baseKey = await crypto.subtle.importKey(
        'raw', new TextEncoder().encode(passphrase), 'PBKDF2', false, ['deriveBits']);
  } catch (e) {
    // some browsers refuse empty passwords
    throw new DecryptionError('unsupported passphrase');
  }
  const bits = await crypto.subtle.deriveBits(
      {name: 'PBKDF2', salt, iterations: derivation.iterations, hash: derivation.hash}, baseKey, 256);
  return new Uint8Array(bits);
}

/**
 * @param {Uint8Array<ArrayBuffer>} keyBytes
 * @param {Uint8Array<ArrayBuffer>} cleartext
 * @param {string} algorithm
 * @param {Uint8Array<ArrayBuffer>} iv
 * @returns {Promise<EncryptedValue>}
 */
async function encryptBytes(keyBytes, cleartext, algorithm, iv) {
  const {aesKey, hmacKey} = await importKeys(keyBytes);
  const ciphertext = await crypto.subtle.encrypt({name: 'AES-CBC', iv}, aesKey, cleartext);
  const signature = await crypto.subtle.sign('HMAC', hmacKey, concat(iv, cleartext));
  return {
    version: 0,
    algorithm,
    iv: toBase64(iv),
    ciphertext: toBase64(new Uint8Array(ciphertext)),
    signature: toBase64(new Uint8Array(signature)),
  };
}

/**
 * @param {Uint8Array<ArrayBuffer>} keyBytes
 * @param {EncryptedValue} value
 * @returns {Promise<Uint8Array<ArrayBuffer>>}
 */
async function decryptBytes(keyBytes, value) {
  if (value.version !== 0) {
    throw new Error('unsupported version: ' + value.version);
  }
  const iv = fromBase64(value.iv);
  const {aesKey, hmacKey} = await importKeys(keyBytes);
  let cleartext;
  try {
    cleartext = new Uint8Array(
        await crypto.subtle.decrypt({name: 'AES-CBC', iv}, aesKey, fromBase64(value.ciphertext)));
  } catch (e) {
    // a wrong key almost always results in invalid padding
    throw new DecryptionError('cannot decrypt');
  }
  if (!await crypto.subtle.verify('HMAC', hmacKey, fromBase64(value.signature), concat(iv, cleartext))) {
    throw new DecryptionError('signature does not match');
  }
  return cleartext;
}

/** @param {Uint8Array<ArrayBuffer>} keyBytes */
async function importKeys(keyBytes) {
  const [aesKey, hmacKey] = await Promise.all([
    crypto.subtle.importKey('raw', keyBytes, 'AES-CBC', false, ['encrypt', 'decrypt']),
    crypto.subtle.importKey('raw', keyBytes, {name: 'HMAC', hash: 'SHA-256'}, false, ['sign', 'verify']),
  ]);
  return {aesKey, hmacKey};
}

function randomIv() {
  return crypto.getRandomValues(new Uint8Array(16));
}

/**
 * @param {Uint8Array<ArrayBuffer>} a
 * @param {Uint8Array<ArrayBuffer>} b
 */
function concat(a, b) {
  const result = new Uint8Array(a.length + b.length);
  result.set(a);
  result.set(b, a.length);
  return result;
}

/** @param {Uint8Array<ArrayBuffer>} bytes */
function toBase64(bytes) {
  return btoa(Array.from(bytes, b => String.fromCharCode(b)).join(''));
}

/** @param {string} text */
function fromBase64(text) {
  return Uint8Array.from(atob(text), c => c.charCodeAt(0));
}
