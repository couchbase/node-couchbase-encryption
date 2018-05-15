/*
 * Copyright (c) 2018 Couchbase, Inc.
 *
 * Use of this software is subject to the Couchbase Inc. Enterprise Subscription License Agreement
 * which may be found at https://www.couchbase.com/ESLA-11132015.
 */

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
