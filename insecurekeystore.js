'use strict';

function InsecureKeyStore() {
  this.keys = {};
}

InsecureKeyStore.prototype.addKey = function(name, value) {
  this.keys[name] = value;
};

InsecureKeyStore.prototype.getKey = function(name) {
  if (this.keys[name]) {
    return this.keys[name];
  }

  throw new Error('invalid key');
};

module.exports = InsecureKeyStore;
