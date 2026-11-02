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

import * as api from './api.js';
import {isLegacyEncryption} from './crypto.js';
import {Dialog, button, h} from './dom.js';
import {Key} from './key.js';

/** @returns {Promise<string>} */
export function askPassphrase() {
  return new Promise(resolve => {
    const dialog = new Dialog('Enter Passphrase');
    const input = h('input', {type: 'password', size: '24', name: 'passphrase'});
    const form = h('form', {}, input, h('input', {type: 'submit', value: 'OK'}));
    form.addEventListener('submit', event => {
      event.preventDefault();
      dialog.close();
      resolve(input.value);
    });
    dialog.content.append(form);
    dialog.show();
    input.focus();
  });
}

/** @typedef {{action: 'select' | 'edit', key: Key} | {action: 'create' | 'different-passphrase'}} KeyChoice */

/**
 * Lists the keys, showing the names of those unlocked with the entered passphrase.
 *
 * @param {Key[]} keys
 * @returns {Promise<KeyChoice>}
 */
export async function chooseKey(keys) {
  const items = await Promise.all(keys.map(async key => {
    const item = h('li');
    if (key.isUnlocked()) {
      item.append(h('span', {}, await key.getName()), ' ', h('span', {}, await key.getDescription()), ' ');
    } else {
      item.append(h('span', {}, 'Key #' + key.id), ' ');
    }
    return item;
  }));

  return new Promise(resolve => {
    const dialog = new Dialog('Secret Keys');
    /** @param {KeyChoice} choice */
    const choose = choice => {
      dialog.close();
      resolve(choice);
    };
    keys.forEach((key, i) => {
      if (key.isUnlocked()) {
        items[i].append(button('select', () => choose({action: 'select', key})), ' ');
      }
      items[i].append(button('edit', () => choose({action: 'edit', key})));
    });
    dialog.content.append(
        h('ul', {}, ...items),
        h('div', {},
            button('Create new key...', () => choose({action: 'create'})), ' ',
            button('Different passphrase...', () => choose({action: 'different-passphrase'}))));
    dialog.show();
  });
}

/** @returns {Promise<Key | null>} the new (unsaved) key, or null if cancelled */
export function createKey() {
  return new Promise(resolve => {
    const dialog = new Dialog('New Key');
    const error = h('div', {class: 'error'});
    const name = h('input', {type: 'text', size: '24', name: 'name'});
    const description = h('input', {type: 'text', size: '24', name: 'description'});
    const passphrase1 = h('input', {type: 'password', size: '24', name: 'passphrase1'});
    const passphrase2 = h('input', {type: 'password', size: '24', name: 'passphrase2'});
    const form = h('form', {},
        h('label', {}, 'Name', name), h('br'),
        h('label', {}, 'Description', description), h('br'),
        h('label', {}, 'Passphrase', passphrase1), h('br'),
        h('label', {}, 'Passphrase (repeat)', passphrase2), h('br'),
        h('input', {type: 'submit', value: 'create'}),
        button('cancel', () => {
          dialog.close();
          resolve(null);
        }, 'dialog-button'));
    form.addEventListener('submit', async event => {
      event.preventDefault();
      if (passphrase1.value !== passphrase2.value || passphrase1.value.length < 1) {
        error.textContent = 'passphrases do not match';
      } else if (name.value.length < 1) {
        error.textContent = 'name cannot be empty';
      } else {
        const key = await Key.create(name.value, description.value, passphrase1.value);
        dialog.close();
        resolve(key);
      }
    });
    dialog.content.append(error, form);
    dialog.show();
    name.focus();
  });
}

/**
 * Lets the user add and remove passphrases of a key, after unlocking it with one of them.
 *
 * @param {Key} key
 * @returns {Promise<void>} resolves once the dialog was closed
 */
export function editKey(key) {
  return new Promise(resolve => {
    const dialog = new Dialog('Edit Key');
    // remembered so the key can be unlocked again after saving changes
    let passphrase = '';
    const passphraseInput = h('input', {type: 'password', size: '24', name: 'passphrase'});
    const encryptionList = h('ul');
    const newEncryptionArea = h('div');

    let saving = Promise.resolve();
    /** @param {() => Promise<boolean | void> | boolean | void} change */
    const save = change => {
      saving = saving.catch(() => {}).then(async () => {
        const changed = await change();
        if (changed !== false) {
          key = new Key(await api.updateKey(key.id, key.toJson()));
          await key.unlock(passphrase);
        }
        render();
      });
      return saving;
    };

    const render = () => {
      encryptionList.replaceChildren(...key.encryptions.map((encryption, i) => {
        const used = key.usedEncryption === i;
        const label = 'Encryption #' + i + (isLegacyEncryption(encryption) ? ' (legacy)' : '');
        const item = h('li', {class: used ? 'encryption-used' : 'encryption-locked'}, h('span', {}, label));
        if (key.isUnlocked() && !used) {
          item.append(' ', button('delete', () => save(() => key.removeEncryption(i))));
        }
        return item;
      }));

      newEncryptionArea.replaceChildren();
      if (key.isUnlocked()) {
        const newPassphrase = h('input', {type: 'password', size: '24', name: 'new-passphrase'});
        newEncryptionArea.append(h('label', {}, 'Add Passphrase', newPassphrase), button('add', () => {
          const value = newPassphrase.value;
          newPassphrase.value = '';
          return value ? save(() => key.addPassphrase(value)) : undefined;
        }, 'dialog-button'));
      }
    };

    dialog.content.append(
        h('label', {}, 'Passphrase', passphraseInput),
        button('try', async () => {
          passphrase = passphraseInput.value;
          passphraseInput.value = '';
          await key.unlock(passphrase);
          render();
          if (!key.isUnlocked()) {
            passphraseInput.focus();
          }
        }, 'dialog-button'),
        encryptionList,
        newEncryptionArea,
        h('div', {}, button('done', async () => {
          await saving;
          dialog.close();
          resolve();
        })));
    render();
    dialog.show();
    passphraseInput.focus();
  });
}

/**
 * Shows all secrets of a key, decrypted, as JSON.
 *
 * @param {Key} key
 */
export async function showExport(key) {
  const dialog = new Dialog('Export Data');
  const textarea = h('textarea', {rows: '30', cols: '80', readonly: ''});
  const download = button('download', () => {
    const link = h('a', {
      href: URL.createObjectURL(new Blob([textarea.value], {type: 'application/json'})),
      download: 'swiss-vault-export.json',
    });
    link.click();
    URL.revokeObjectURL(link.href);
  });
  download.disabled = true;
  dialog.content.append(textarea, h('div', {}, download, ' ', button('close', () => dialog.close())));
  dialog.show();

  /** @type {{name: string, description: string, properties: {name: string, value: string}[]}[]} */
  const data = [];
  for (const secret of await api.listSecrets(key.id)) {
    const properties = await api.listProperties(key.id, secret.id);
    data.push({
      name: await key.decrypt(secret.name),
      description: await key.decrypt(secret.description),
      properties: await Promise.all(properties.map(async property => ({
        name: await key.decrypt(property.name),
        value: await key.decrypt(property.value),
      }))),
    });
    textarea.value = JSON.stringify(data, null, 2);
  }
  download.disabled = false;
}
