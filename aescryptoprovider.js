/*
 * Copyright (c) 2018 Couchbase, Inc.
 *
 * Use of this software is subject to the Couchbase Inc. Enterprise Subscription License Agreement
 * which may be found at https://www.couchbase.com/ESLA-11132015.
 */

'use strict';

var crypto = require('crypto');

function AesCryptoProvider(keyProvider, key, hmacKey) {
  if (!hmacKey) {
    hmacKey = key;
  }

  this.keyProvider = keyProvider;
  this.key = key;
  this.hmacKey = hmacKey;
}

AesCryptoProvider.prototype.algNameFromKey = function(key, hmacKey) {
  switch (key.length) {
    case 32:
      return 'AES-256-HMAC-SHA256';
    default:
      throw new Error('invalid cipher key size (must be 32 bytes).');
  }
};

AesCryptoProvider.prototype.encrypt = function(data) {
  var key = this.keyProvider.getKey(this.key);

  var hmacKey = key;
  if (this.hmacKey) {
    hmacKey = this.keyProvider.getKey(this.hmacKey);
  }

  var algName = this.algNameFromKey(key, hmacKey);

  var iv = crypto.randomBytes(16);
  var codedIv = iv.toString('base64');

  var cipher = null;
  switch(algName) {
    case 'AES-256-HMAC-SHA256':
      cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
      break;
  }

  if (!cipher) {
    throw new Error('generated algorithm name was not recognized');
  }

  var dataStr = JSON.stringify(data);
  var codedCiphertext = cipher.update(dataStr, 'utf8', 'base64') + cipher.final('base64');

  var sigData =
      this.key +
      algName +
      codedIv +
      codedCiphertext;
  var codedSig = crypto.createHmac('sha256', hmacKey).update(sigData).digest('base64');

  return {
    alg: algName,
    kid: this.key,
    iv: codedIv,
    ciphertext: codedCiphertext,
    sig: codedSig
  }
};

AesCryptoProvider.prototype.decrypt = function(data) {
  var key = this.keyProvider.getKey(this.key);

  var hmacKey = key;
  if (this.hmacKey) {
    hmacKey = this.keyProvider.getKey(this.hmacKey);
  }

  var algName = this.algNameFromKey(key, hmacKey);

  if (data.kid !== this.key) {
    throw new Error('encryption key did not match configured key.');
  }

  if (data.alg !== algName) {
    throw new Error('encryption algorithm did not match the configured algorithm.');
  }

  var sigData =
      this.key +
      algName +
      data.iv +
      data.ciphertext;

  var sig = crypto.createHmac('sha256', hmacKey).update(sigData).digest('base64');
  if (sig !== data.sig) {
    throw new Error('encrypted data was tampered');
  }

  var cipherData = Buffer.from(data.ciphertext, 'base64')
  var iv = Buffer.from(data.iv, 'base64');

  var decipher = null;
  switch(algName) {
    case 'AES-256-HMAC-SHA256':
      decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
      break;
  }

  if (!decipher) {
    throw new Error('generated algorithm name was not recognized');
  }

  var decrypted = decipher.update(cipherData, 'base64', 'utf8') +
      decipher.final('utf8');

  return JSON.parse(decrypted);
};

module.exports = AesCryptoProvider;
