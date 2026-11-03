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
import {generatePassword, showExport} from './dialogs.js';
import {button, h} from './dom.js';

/** @typedef {import('./key.js').Key} Key */
/** @typedef {{id: string, name: string, description: string}} Secret decrypted */
/** @typedef {{id: string, name: string, value: string}} Property decrypted */

/**
 * Shows the secrets of an unlocked key, sorted by name.
 *
 * @param {Key} key
 */
export async function showSecrets(key) {
  const secrets = await Promise.all((await api.listSecrets(key.id)).map(async secret => ({
    id: secret.id,
    name: await key.decrypt(secret.name),
    description: await key.decrypt(secret.description),
  })));
  secrets.sort((a, b) => a.name.localeCompare(b.name, undefined, {sensitivity: 'base'}));

  const panes = secrets.map(secret => new SecretPane(key, secret));
  const list = h('ul', {class: 'secretList'}, ...panes.map(pane => pane.element));

  // hides the secrets whose name and description do not contain every word typed
  const search = h('input', {type: 'search', class: 'search', placeholder: 'Search', 'aria-label': 'Search secrets'});
  const filter = () => {
    const words = search.value.toLocaleLowerCase().split(/\s+/).filter(word => word);
    for (const pane of panes) {
      pane.element.hidden = !pane.matches(words);
    }
  };
  search.addEventListener('input', filter);
  // some browsers clear search fields on escape without an input event
  search.addEventListener('search', filter);

  document.body.append(
      h('div', {class: 'searchBar'}, search, h('a', {href: '/logout', class: 'link'}, 'logout')),
      list,
      h('div', {class: 'mainOptions'},
      button('new secret', () => {
        const pane = new SecretPane(key, null);
        panes.push(pane);
        list.append(pane.element);
        pane.nameInput.focus();
      }, 'button'),
      button('export data', () => showExport(key), 'button')));
  search.focus();
}

class SecretPane {
  /**
   * @param {Key} key
   * @param {Secret | null} secret null for a new, not yet saved secret
   */
  constructor(key, secret) {
    this.key = key;
    this.secret = secret;
    this.expanded = false;
    // incremented on every expand/collapse, so properties that arrive late are dropped
    this.generation = 0;

    this.toggle = button('+', () => this.setExpanded(!this.expanded), 'toggle');

    this.name = h('div', {class: 'secretName'});
    this.description = h('div', {class: 'secretDescription'});
    // the spaces keep double-click selection from spanning name and description
    this.readOnlyFields = h('div', {class: 'secretTitle'},
        this.name, ' ', this.description, ' ', button('edit', () => this.showEditableFields(), 'button'));

    this.nameInput = h('input', {type: 'text', class: 'secretName secretNameEdit'});
    this.descriptionInput = h('input', {type: 'text', class: 'secretDescription secretDescriptionEdit'});
    this.editableFields = h('div', {class: 'secretTitle'},
        this.nameInput, this.descriptionInput, button('save', () => this.save(), 'button'));

    this.header = h('div');
    this.properties = h('ul', {class: 'propertyList'});
    this.content = h('div', {hidden: ''}, this.properties, h('div', {},
        button('add property', () => this.addProperty(null), 'button'),
        button('delete secret', () => this.delete(), 'button')));
    this.element = h('li', {class: 'secretListItem'}, this.header, this.content);

    if (this.secret) {
      this.showReadOnlyFields();
    } else {
      this.showEditableFields();
    }
  }

  /**
   * @param {string[]} words lower case
   * @returns {boolean} whether the name or description contains all words; a new, unsaved secret always matches
   */
  matches(words) {
    if (!this.secret) {
      return true;
    }
    const text = (this.secret.name + ' ' + this.secret.description).toLocaleLowerCase();
    return words.every(word => text.includes(word));
  }

  showReadOnlyFields() {
    const secret = this.savedSecret();
    this.name.textContent = secret.name;
    this.description.textContent = secret.description;
    this.header.replaceChildren(this.toggle, this.readOnlyFields);
  }

  showEditableFields() {
    this.nameInput.value = this.secret?.name ?? '';
    this.descriptionInput.value = this.secret?.description ?? '';
    this.header.replaceChildren(...(this.secret ? [this.toggle] : []), this.editableFields);
  }

  async save() {
    const name = this.nameInput.value;
    const description = this.descriptionInput.value;
    const json = {name: await this.key.encrypt(name), description: await this.key.encrypt(description)};
    const saved = this.secret
        ? await api.updateSecret(this.key.id, this.secret.id, json)
        : await api.createSecret(this.key.id, json);
    this.secret = {id: saved.id, name, description};
    this.showReadOnlyFields();
  }

  /** @param {boolean} expanded */
  async setExpanded(expanded) {
    const generation = ++this.generation;
    this.expanded = expanded;
    this.toggle.textContent = expanded ? '-' : '+';
    this.content.hidden = !expanded;
    this.properties.replaceChildren();
    if (!expanded) {
      return;
    }

    const secret = this.savedSecret();
    const properties = await Promise.all((await api.listProperties(this.key.id, secret.id)).map(async property => ({
      id: property.id,
      name: await this.key.decrypt(property.name),
      value: await this.key.decrypt(property.value),
    })));
    if (generation !== this.generation) {
      return;
    }
    for (const property of properties) {
      this.addProperty(property);
    }
    if (properties.length === 0) {
      this.addProperty(null);
    }
  }

  /** @param {Property | null} property */
  addProperty(property) {
    this.properties.append(new PropertyPane(this.key, this.savedSecret(), property).element);
  }

  async delete() {
    if (confirm('Are you sure you want to delete this secret and all its properties?')) {
      await api.deleteSecret(this.key.id, this.savedSecret().id);
      this.element.remove();
    }
  }

  savedSecret() {
    if (!this.secret) {
      throw new Error('secret has not been saved yet');
    }
    return this.secret;
  }
}

class PropertyPane {
  /**
   * @param {Key} key
   * @param {Secret} secret
   * @param {Property | null} property null for a new, not yet saved property
   */
  constructor(key, secret, property) {
    this.key = key;
    this.secret = secret;
    this.property = property;

    this.name = h('div', {class: 'propertyName'});
    this.value = h('div', {class: 'propertyValue'});
    // the spaces keep double-click selection from spanning name and value
    this.readOnlyFields = h('div', {},
        this.name, ' ', this.value, ' ', button('edit', () => this.showEditableFields(), 'button'));

    this.nameInput = h('input', {type: 'text', class: 'propertyName propertyNameEdit'});
    this.valueInput = h('input', {type: 'text', class: 'propertyValue propertyValueEdit'});
    this.generateButton = button('generate', async () => {
      const password = await generatePassword();
      if (password !== null) {
        this.valueInput.value = password;
        this.valueInput.focus();
      }
    }, 'button');
    this.deleteButton = button('delete property', () => this.delete(), 'button');
    this.editableFields = h('div', {},
        this.nameInput, this.valueInput, this.generateButton, button('save property', () => this.save(), 'button'));

    this.element = h('li', {class: 'propertyListItem'});
    if (this.property) {
      this.showReadOnlyFields();
    } else {
      this.showEditableFields();
    }
  }

  showReadOnlyFields() {
    const property = this.savedProperty();
    this.name.textContent = property.name;
    this.value.textContent = property.value;
    this.element.replaceChildren(this.readOnlyFields);
  }

  showEditableFields() {
    this.nameInput.value = this.property?.name ?? '';
    this.valueInput.value = this.property?.value ?? '';
    if (this.property) {
      this.editableFields.append(this.deleteButton);
    }
    this.element.replaceChildren(this.editableFields);
  }

  async save() {
    const name = this.nameInput.value;
    const value = this.valueInput.value;
    const json = {name: await this.key.encrypt(name), value: await this.key.encrypt(value)};
    const saved = this.property
        ? await api.updateProperty(this.key.id, this.secret.id, this.property.id, json)
        : await api.createProperty(this.key.id, this.secret.id, json);
    this.property = {id: saved.id, name, value};
    this.showReadOnlyFields();
  }

  async delete() {
    if (confirm('Are you sure you want to delete this property?')) {
      await api.deleteProperty(this.key.id, this.secret.id, this.savedProperty().id);
      this.element.remove();
    }
  }

  savedProperty() {
    if (!this.property) {
      throw new Error('property has not been saved yet');
    }
    return this.property;
  }
}
