'use strict';

/**
 * KeyProvider provides methods for crypto providers to fetch the
 * necessary keys for encryption and decryption.
 *
 * @constructor
 */
function KeyProvider() {
}

/**
 * getKey returns a key by name.
 *
 * @param {string} name
 * @return Buffer
 */
KeyProvider.prototype.getKey = function(name) {
  throw new Error('not implemented');
};

module.exports = KeyProvider;
