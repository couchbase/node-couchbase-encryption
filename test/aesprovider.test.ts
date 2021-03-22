import { expect } from 'chai'
import { AeadAes256CbcHmacSha512Provider } from '../lib/aesprovider'
import { EncryptionResult } from '../lib/encryptionresult'
import { InvalidCipherTextError, KeyInvalidError, KeyNotFoundError } from '../lib/errors'
import { InsecureKeyring, Key } from '../lib/keyring'

describe('Aes provider', () => {
    it('should encrypt and decrypt', () => {
        const keyVal = Buffer.from('000102030405060708090a0b0c0d0e0f'+
                                   '101112131415161718191a1b1c1d1e1f'+
                                   '202122232425262728292a2b2c2d2e2f'+
                                   '303132333435363738393a3b3c3d3e3f', 'hex')
        const iv = Buffer.from('1af38c2dc2b96ffdd86694092341bc04', 'hex')

        const doc = Buffer.from(JSON.stringify('The enemy knows the system.'), 'utf8')

        const key = new Key('test-key', keyVal)
        const keyring  = new InsecureKeyring(key)

        const provider = new AeadAes256CbcHmacSha512Provider(keyring)
        const encrypter = provider.encrypterForKey('test-key')
        const result = encrypter.encryptWithExtras(doc, iv)
        expect(result.algorithm()).equal('AEAD_AES_256_CBC_HMAC_SHA512')
        expect(result.kid()).equal('test-key')
        expect(result.ciphertext()).equal('GvOMLcK5b/3YZpQJI0G8BLm98oj20ZLdqKDV3MfTuGlWL4R5p5Deykuv2XLW4LcDvnOkmhuUSRbQ8QVEmbjq43XHdOm3ColJ6LzoaAtJihk=')

        const dec = provider.decrypter().decrypt(result)
        expect(dec.toString()).equal('The enemy knows the system.')
    })

    it('should encrypt and decrypt with associated data', () => {
        const keyVal = Buffer.from('000102030405060708090a0b0c0d0e0f'+
                                   '101112131415161718191a1b1c1d1e1f'+
                                   '202122232425262728292a2b2c2d2e2f'+
                                   '303132333435363738393a3b3c3d3e3f', 'hex')
        const iv = Buffer.from('1af38c2dc2b96ffdd86694092341bc04', 'hex')

        const doc = Buffer.from('41206369706865722073797374656d20'+
                                '6d757374206e6f742062652072657175'+
                                '6972656420746f206265207365637265'+
                                '742c20616e64206974206d7573742062'+
                                '652061626c6520746f2066616c6c2069'+
                                '6e746f207468652068616e6473206f66'+
                                '2074686520656e656d7920776974686f'+
                                '757420696e636f6e76656e69656e6365', 'hex')
        const assocData = Buffer.from('546865207365636f6e64207072696e63'+
                                      '69706c65206f66204175677573746520'+
                                      '4b6572636b686f666673', 'hex')

        const key = new Key('test-key', keyVal)
        const keyring  = new InsecureKeyring(key)

        const provider = new AeadAes256CbcHmacSha512Provider(keyring)
        const encrypter = provider.encrypterForKey('test-key')
        const result = encrypter.encryptWithExtras(doc, iv, assocData)
        expect(result.algorithm()).equal('AEAD_AES_256_CBC_HMAC_SHA512')
        expect(result.kid()).equal('test-key')

        const expected = 'GvOMLcK5b/3YZpQJI0G8BEr/qq23jDHF2ksbWQ0Q/7092NXTAkI1JpEtoDfsvMe9giwwHdZ8NzvMtYStPpJ5wubRKhN0t38HdVPfgpQQRGs269lwZilq5kJ+p1wuCEahGgnM9TcNyAv+y60oxz8Js6O3XmYqJZRBCuSWsuLmYJ4x5uAsyDfwU9IfN/9PUZULviY40J3XpJMJMIBtBwOx9k3TtMCIp/RcIWg5ZFsgEr8uYmmoxWqBbbwbJndhlVvF'
        expect(result.ciphertext()).equal(expected)

        const dec = provider.decrypter().decryptWithExtras(result, assocData)
        expect(dec).deep.equal(doc)
    })

    it('should throw when encrypting with a missing crypto key', () => {
        const doc = 'The enemy knows the system.'

        const keyring  = new InsecureKeyring()

        const provider = new AeadAes256CbcHmacSha512Provider(keyring)
        const encrypter = provider.encrypterForKey('test-key')
        expect(() => encrypter.encrypt(doc)).to.throw(KeyNotFoundError)
    })

    it('should throw when encrypting with an invalid crypto key', () => {
        const keyVal = Buffer.from('000102030405060708090a0b0c0d0e0f'+
                                   '101112131415161718191a1b1c1d1e1f'+
                                   '202122232425262728292a2b2c2d2e2f'+
                                   '333435363738393a3b3c3d3e3f', 'hex')

        const doc = 'The enemy knows the system.'

        const key = new Key('test-key', keyVal)
        const keyring  = new InsecureKeyring(key)

        const provider = new AeadAes256CbcHmacSha512Provider(keyring)
        const encrypter = provider.encrypterForKey('test-key')
        expect(() => encrypter.encrypt(doc)).to.throw(KeyInvalidError)
    })

    it('should throw when decrypting with an invalid crypto key', () => {
        const keyVal = Buffer.from('000102030405060708090a0b0c0d0e0f'+
                                   '101112131415161718191a1b1c1d1e1f'+
                                   '202122232425262728292a2b2c2d2e2f'+
                                   '333435363738393a3b3c3d3e3f', 'hex')

        const doc = 'The enemy knows the system.'

        const key = new Key('test-key', keyVal)
        const keyring  = new InsecureKeyring(key)

        const provider = new AeadAes256CbcHmacSha512Provider(keyring)
        const decrypter = provider.decrypter()

        expect(() => decrypter.decrypt(new EncryptionResult({
            alg: 'AEAD_AES_256_CBC_HMAC_SHA512',
            kid: 'test-key',
            ciphertext: 'GvOMLcK5b/3YZpQJI0G8BLm98oj20ZLdqKDV3MfTuGlWL4R5p5Deykuv2XLW4LcDvnOkmhuUSRbQ8QVEmbjq43XHdOm3ColJ6LzoaAtJihk='
        }))).to.throw(KeyInvalidError)
    })

    it('should throw when decrypting with a missing crypto key', () => {
        const doc = 'The enemy knows the system.'

        const keyring  = new InsecureKeyring()

        const provider = new AeadAes256CbcHmacSha512Provider(keyring)
        const decrypter = provider.decrypter()

        expect(() => decrypter.decrypt(new EncryptionResult({
            alg: 'AEAD_AES_256_CBC_HMAC_SHA512',
            kid: 'test-key',
            ciphertext: 'GvOMLcK5b/3YZpQJI0G8BLm98oj20ZLdqKDV3MfTuGlWL4R5p5Deykuv2XLW4LcDvnOkmhuUSRbQ8QVEmbjq43XHdOm3ColJ6LzoaAtJihk='
        }))).to.throw(KeyNotFoundError)
    })

    it('should throw when cipher text is invalid', () => {
        const keyVal = Buffer.from('000102030405060708090a0b0c0d0e0f'+
                                   '101112131415161718191a1b1c1d1e1f'+
                                   '202122232425262728292a2b2c2d2e2f'+
                                   '303132333435363738393a3b3c3d3e3f', 'hex')

        const doc = 'The enemy knows the system.'

        const key = new Key('test-key', keyVal)
        const keyring  = new InsecureKeyring(key)

        const provider = new AeadAes256CbcHmacSha512Provider(keyring)
        const decrypter = provider.decrypter()

        expect(() => decrypter.decrypt(new EncryptionResult({
            alg: 'AEAD_AES_256_CBC_HMAC_SHA512',
            kid: 'test-key',
            ciphertext: 'GGvOMLcK5b/3YZpQJI0G8BLm98oj20ZLdqKDV3MfTuGlWL4RLzoaAtJihk='
        }))).to.throw(InvalidCipherTextError)
    })
})