import { Key, InsecureKeyring } from '../lib/keyring'
import { LegacyAes256Decrypter } from '../lib/legacyaesdecrypter'
import { EncryptionResult } from '../lib/encryptionresult'
import { expect } from 'chai'
import { InvalidCipherTextError, KeyInvalidError, KeyNotFoundError } from '../lib/errors'

describe('legacy aes decrypter', () => {
    it('should decrypt a string created by v1', () => {
        const doc = {
            alg: 'AES-256-HMAC-SHA256',
            kid: 'mypublickey',
            iv: 'Cfq84/46Qjet3EEQ1HUwSg==',
            ciphertext: 'sR6AFEIGWS5Fy9QObNOhbCgfg3vXH4NHVRK1qkhKLQqjkByg2n69lot89qFEJuBsVNTXR77PZR6RjN4h4M9evg==',
            sig: 'rT89aCj1WosYjWHHu0mf92S195vYnEGA/reDnYelQsM='
        }

        const key = new Key('mypublickey', Buffer.from('!mysecretkey#9^5usdk39d&dlf)03sL'))
        const privkey = new Key('myhmackey', Buffer.from('myauthpassword'))
        const keyring  = new InsecureKeyring(key, privkey)

        const decrypter = new LegacyAes256Decrypter(keyring, function(publicKey: string):string  {
            if (publicKey == 'mypublickey') {
                return 'myhmackey'
            }

            throw new Error()
        })

        const result = decrypter.decrypt(new EncryptionResult(doc))
        expect(result).deep.equal('The old grey goose jumped over the wrickety gate.')
    })

    it('should error when a key is missing', () => {
        const doc = {
            alg: 'AES-256-HMAC-SHA256',
            kid: 'mypublickey',
            iv: 'Cfq84/46Qjet3EEQ1HUwSg==',
            ciphertext: 'sR6AFEIGWS5Fy9QObNOhbCgfg3vXH4NHVRK1qkhKLQqjkByg2n69lot89qFEJuBsVNTXR77PZR6RjN4h4M9evg==',
            sig: 'rT89aCj1WosYjWHHu0mf92S195vYnEGA/reDnYelQsM='
        }

        const privkey = new Key('myhmackey', Buffer.from('myauthpassword'))
        const keyring  = new InsecureKeyring(privkey)

        const decrypter = new LegacyAes256Decrypter(keyring, function(publicKey: string):string  {
            if (publicKey == 'mypublickey') {
                return 'myhmackey'
            }

            throw new Error()
        })

        expect(() => decrypter.decrypt(new EncryptionResult(doc))).to.throw(KeyNotFoundError)
    })

    it('should error when a private key is missing', () => {
        const doc = {
            alg: 'AES-256-HMAC-SHA256',
            kid: 'mypublickey',
            iv: 'Cfq84/46Qjet3EEQ1HUwSg==',
            ciphertext: 'sR6AFEIGWS5Fy9QObNOhbCgfg3vXH4NHVRK1qkhKLQqjkByg2n69lot89qFEJuBsVNTXR77PZR6RjN4h4M9evg==',
            sig: 'rT89aCj1WosYjWHHu0mf92S195vYnEGA/reDnYelQsM='
        }

        const key = new Key('mypublickey', Buffer.from('!mysecretkey#9^5usdk39d&dlf)03sL'))
        const keyring  = new InsecureKeyring(key)

        const decrypter = new LegacyAes256Decrypter(keyring, function(publicKey: string):string  {
            if (publicKey == 'mypublickey') {
                return 'myhmackey'
            }

            throw new Error()
        })

        expect(() => decrypter.decrypt(new EncryptionResult(doc))).to.throw(KeyNotFoundError)
    })

    it('should error when iv is missing', () => {
        const doc = {
            alg: 'AES-256-HMAC-SHA256',
            kid: 'mypublickey',
            ciphertext: 'sR6AFEIGWS5Fy9QObNOhbCgfg3vXH4NHVRK1qkhKLQqjkByg2n69lot89qFEJuBsVNTXR77PZR6RjN4h4M9evg==',
            sig: 'rT89aCj1WosYjWHHu0mf92S195vYnEGA/reDnYelQsM='
        }

        const key = new Key('mypublickey', Buffer.from('!mysecretkey#9^5usdk39d&dlf)03sL'))
        const privkey = new Key('myhmackey', Buffer.from('myauthpassword'))
        const keyring  = new InsecureKeyring(key, privkey)

        const decrypter = new LegacyAes256Decrypter(keyring, function(publicKey: string):string  {
            if (publicKey == 'mypublickey') {
                return 'myhmackey'
            }

            throw new Error()
        })

        expect(() => decrypter.decrypt(new EncryptionResult(doc))).to.throw()
    })

    it('should error when an non-matching algorithm is used', () => {
        const doc = {
            alg: 'RSA',
            kid: 'mypublickey',
            iv: 'Cfq84/46Qjet3EEQ1HUwSg==',
            ciphertext: 'sR6AFEIGWS5Fy9QObNOhbCgfg3vXH4NHVRK1qkhKLQqjkByg2n69lot89qFEJuBsVNTXR77PZR6RjN4h4M9evg==',
            sig: 'rT89aCj1WosYjWHHu0mf92S195vYnEGA/reDnYelQsM='
        }

        const key = new Key('mypublickey', Buffer.from('!mysecretkey#9^5usdk39d&dlf)03sL'))
        const privkey = new Key('myhmackey', Buffer.from('myauthpassword'))
        const keyring  = new InsecureKeyring(key, privkey)

        const decrypter = new LegacyAes256Decrypter(keyring, function(publicKey: string):string  {
            if (publicKey == 'mypublickey') {
                return 'myhmackey'
            }

            throw new Error()
        })

        expect(() => decrypter.decrypt(new EncryptionResult(doc))).to.throw()
    })

    it('should error when sig is missing', () => {
        const doc = {
            alg: 'AES-256-HMAC-SHA256',
            kid: 'mypublickey',
            iv: 'Cfq84/46Qjet3EEQ1HUwSg==',
            ciphertext: 'sR6AFEIGWS5Fy9QObNOhbCgfg3vXH4NHVRK1qkhKLQqjkByg2n69lot89qFEJuBsVNTXR77PZR6RjN4h4M9evg==',
        }

        const key = new Key('mypublickey', Buffer.from('!mysecretkey#9^5usdk39d&dlf)03sL'))
        const privkey = new Key('myhmackey', Buffer.from('myauthpassword'))
        const keyring  = new InsecureKeyring(key, privkey)

        const decrypter = new LegacyAes256Decrypter(keyring, function(publicKey: string):string  {
            if (publicKey == 'mypublickey') {
                return 'myhmackey'
            }

            throw new Error()
        })

        expect(() => decrypter.decrypt(new EncryptionResult(doc))).to.throw()
    })

    it('should error with an invalid ciphertext', () => {
        const doc = {
            alg: 'AES-256-HMAC-SHA256',
            kid: 'mypublickey',
            iv: 'Cfq84/46Qjet3EEQ1HUwSg==',
            ciphertext: 'sR6AFEIGWS5Fy9QObNOhbCgfg3vXH4NHVRK1qkhKLQqjkByg2n69lot89=',
            sig: 'rT89aCj1WosYjWHHu0mf92S195vYnEGA/reDnYelQsM='
        }

        const key = new Key('mypublickey', Buffer.from('!mysecretkey#9^5usdk39d&dlf)03sL'))
        const privkey = new Key('myhmackey', Buffer.from('myauthpassword'))
        const keyring  = new InsecureKeyring(key, privkey)

        const decrypter = new LegacyAes256Decrypter(keyring, function(publicKey: string):string  {
            if (publicKey == 'mypublickey') {
                return 'myhmackey'
            }

            throw new Error()
        })

        expect(() => decrypter.decrypt(new EncryptionResult(doc))).to.throw(InvalidCipherTextError)
    })
})