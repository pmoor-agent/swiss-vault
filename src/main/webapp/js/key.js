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

import {decrypt, encrypt, isLegacyEncryption, newRawSecret, unwrapSecret, wrapSecret} from './crypto.js';

/** @typedef {import('./api.js').KeyJson} KeyJson */
/** @typedef {import('./crypto.js').EncryptedValue} EncryptedValue */

/**
 * A key encrypts the secrets stored under it with its random raw secret. The raw secret itself is
 * stored once per passphrase, wrapped with that passphrase ("encryptions").
 */
export class Key {
  /** @param {KeyJson} json */
  constructor(json) {
    this.json = json;
    /** @type {Uint8Array<ArrayBuffer> | null} */
    this.rawSecret = null;
    /** index of the encryption whose passphrase unlocked this key, or -1 */
    this.usedEncryption = -1;
  }

  /**
   * @param {string} name
   * @param {string} description
   * @param {string} passphrase
   */
  static async create(name, description, passphrase) {
    const rawSecret = newRawSecret();
    const key = new Key({
      name: await encrypt(rawSecret, name),
      description: await encrypt(rawSecret, description),
      encryptions: [await wrapSecret(passphrase, rawSecret)],
    });
    key.rawSecret = rawSecret;
    key.usedEncryption = 0;
    return key;
  }

  get id() {
    if (!this.json.id) {
      throw new Error('key has not been saved yet');
    }
    return this.json.id;
  }

  get encryptions() {
    return this.json.encryptions;
  }

  isUnlocked() {
    return this.rawSecret !== null;
  }

  /**
   * @param {string} passphrase
   * @returns {Promise<boolean>} whether one of the key's passphrases matched
   */
  async unlock(passphrase) {
    this.rawSecret = null;
    this.usedEncryption = -1;
    // current encryptions first: once the same passphrase has a current and a legacy encryption, the
    // current one counts as used, which leaves the legacy one deletable
    const indexes = [...this.encryptions.keys()].sort(
        (a, b) => Number(isLegacyEncryption(this.encryptions[a])) - Number(isLegacyEncryption(this.encryptions[b])));
    for (const index of indexes) {
      const rawSecret = await unwrapSecret(passphrase, this.encryptions[index]);
      if (rawSecret) {
        this.rawSecret = rawSecret;
        this.usedEncryption = index;
        return true;
      }
    }
    return false;
  }

  /**
   * Adds a passphrase that unlocks this key, unless it already does with a current encryption. Adding
   * a passphrase that only unlocks a legacy encryption upgrades it: the legacy one can then be deleted.
   *
   * @param {string} passphrase
   */
  async addPassphrase(passphrase) {
    for (const encryption of this.encryptions) {
      if (!isLegacyEncryption(encryption) && await unwrapSecret(passphrase, encryption)) {
        return;
      }
    }
    this.encryptions.push(await wrapSecret(passphrase, this.unlockedSecret()));
  }

  /** @param {number} index */
  removeEncryption(index) {
    this.encryptions.splice(index, 1);
  }

  /** @param {string} cleartext */
  encrypt(cleartext) {
    return encrypt(this.unlockedSecret(), cleartext);
  }

  /** @param {EncryptedValue} value */
  decrypt(value) {
    return decrypt(this.unlockedSecret(), value);
  }

  getName() {
    return this.decrypt(this.json.name);
  }

  getDescription() {
    return this.decrypt(this.json.description);
  }

  /** @returns {KeyJson} */
  toJson() {
    return {name: this.json.name, description: this.json.description, encryptions: this.encryptions};
  }

  unlockedSecret() {
    if (!this.rawSecret) {
      throw new Error('key is locked');
    }
    return this.rawSecret;
  }
}
