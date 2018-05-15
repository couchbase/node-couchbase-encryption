/*
 * Copyright (c) 2018 Couchbase, Inc.
 *
 * Use of this software is subject to the Couchbase Inc. Enterprise Subscription License Agreement
 * which may be found at https://www.couchbase.com/ESLA-11132015.
 */

'use strict';

/**
 * CryptoProvider describes an interface for field encryption
 * to encrypt and decrypt fields with.
 *
 * @constructor
 */
function CryptoProvider() {
}

/**
 * encrypt perform encryption on a field and returns the encrypted data.
 *
 * @param {Object} data
 * @returns {Object}
 */
CryptoProvider.prototype.encrypt = function(data) {
  throw new Error('not implemented');
};

/**
 * decrypt perform encryption on a field and returns the encrypted data.
 *
 * @param {Object} data
 * @returns {Object}
 */
CryptoProvider.prototype.decrypt = function(data) {
  throw new Error('not implemented');
};

module.exports = CryptoProvider;
