/*
 * Copyright (c) 2018 Couchbase, Inc.
 *
 * Use of this software is subject to the Couchbase Inc. Enterprise Subscription License Agreement
 * which may be found at https://www.couchbase.com/ESLA-11132015.
 */

'use strict';

exports.InsecureKeyStore = require('./insecurekeystore');
exports.AesCryptoProvider = require('./aescryptoprovider');

/**
 * encryptFields will take a document and perform encryption on
 * various fields, as specified by the field/provider map passed.
 * 
 * @param {Object} doc 
 * @param {Map<string,CryptoProvider>} fields
 * @returns {Object}
 */
exports.encryptFields = function(doc, fields) {
  var docOut = {};
  for (var i in doc) {
    if (doc.hasOwnProperty(i)) {
      docOut[i] = doc[i];
    }
  }

  for (var i in fields) {
    if (fields.hasOwnProperty(i)) {
      if (doc[i] !== undefined) {
        var encrypted = fields[i].encrypt(doc[i]);

        delete docOut[i];
        docOut['__crypt_' + i] = encrypted;
      }
    }
  }

  return docOut;
};

/**
 * decryptFields will take a document and perform decryption on
 * various fields, as specified by the field/provider map passed.
 * 
 * @param {Object} doc 
 * @param {Map<string,CryptoProvider>} fields
 * @returns {Object}
 */
exports.decryptFields = function(doc, fields) {
  var docOut = {};
  for (var i in doc) {
    if (doc.hasOwnProperty(i)) {
      docOut[i] = doc[i];
    }
  }

  for (var i in fields) {
    if (fields.hasOwnProperty(i)) {
      if (doc['__crypt_' + i] !== undefined) {
        var decrypted = fields[i].decrypt(doc['__crypt_' + i]);

        delete docOut['__crypt_' + i];
        docOut[i] = decrypted;
      }
    }
  }

  return docOut;
};
