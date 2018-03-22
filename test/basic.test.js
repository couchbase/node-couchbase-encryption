var assert = require('assert');
var cbfieldcrypt = require('../index');

it('should successfully round-trip data', function() {
  var testKey = Buffer.from('1234567890123456123456789012345612345678901234561234567890123456', 'hex');

  var keyStore = new cbfieldcrypt.InsecureKeyStore();
  keyStore.addKey('somekey', testKey);
  keyStore.addKey('hmackey', testKey);

  var fields = {
    cryptString: new cbfieldcrypt.AesCryptoProvider(keyStore, 'somekey', 'hmackey'),
    cryptNum: new cbfieldcrypt.AesCryptoProvider(keyStore, 'somekey', 'hmackey'),
    cryptStruct: new cbfieldcrypt.AesCryptoProvider(keyStore, 'somekey', 'hmackey')
  };

  var testObj = {
    noCrypt:'Hello',
    cryptString:'World',
    cryptNum:1337,
    cryptStruct:{
      testString: 'Franklyn',
      testNum:1448
    }
  };


  var encData = cbfieldcrypt.encryptFields(testObj, fields);
  var decData = cbfieldcrypt.decryptFields(encData, fields);

  assert.deepStrictEqual(testObj, decData);
});

it('should successfully decode data from another SDK', function() {
  var keyStore = new cbfieldcrypt.InsecureKeyStore();
  keyStore.addKey('mypublickey', new Buffer('!mysecretkey#9^5usdk39d&dlf)03sL'));
  keyStore.addKey('myhmackey', new Buffer('myauthpassword'));

  var fields = {
    message: new cbfieldcrypt.AesCryptoProvider(keyStore, 'mypublickey', 'myhmackey'),
  };

  var doc = {
    __crypt_message: {
      alg: "AES-256-HMAC-SHA256",
      kid: "mypublickey",
      iv: "Cfq84/46Qjet3EEQ1HUwSg==",
      ciphertext: "sR6AFEIGWS5Fy9QObNOhbCgfg3vXH4NHVRK1qkhKLQqjkByg2n69lot89qFEJuBsVNTXR77PZR6RjN4h4M9evg==",
      sig: "rT89aCj1WosYjWHHu0mf92S195vYnEGA/reDnYelQsM="
    }
  };

  var decDoc = cbfieldcrypt.decryptFields(doc, fields);
  assert.deepStrictEqual(decDoc, {
    message: 'The old grey goose jumped over the wrickety gate.'
  });
});
