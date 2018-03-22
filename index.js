exports.InsecureKeyStore = require('./insecurekeystore');
exports.AesCryptoProvider = require('./aescryptoprovider');

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
