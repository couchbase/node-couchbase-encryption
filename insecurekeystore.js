/*
 * Copyright (c) 2018 Couchbase, Inc.
 *
 * Use of this software is subject to the Couchbase Inc. Enterprise Subscription License Agreement
 * which may be found at https://www.couchbase.com/ESLA-11132015.
 */

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
