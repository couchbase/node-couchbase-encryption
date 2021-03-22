import { DefaultCryptoManager } from '../lib/crypto'
import { AeadAes256CbcHmacSha512Provider } from '../lib/aesprovider';
import { InsecureKeyring, Key } from '../lib/keyring';
import { expect } from 'chai';
import { EncryptionResult } from '../lib/encryptionresult';

interface PersonStreet {
    firstLine?: string
    secondLine?: string
}

interface PersonAddress {
    houseName?: string
    street?: PersonStreet[]
    attributes?: {[key: string]: PetAttribute}
}

interface PetAttribute {
    action: string
    extra?: string
}

interface Pet {
    animal: string
    attributes?: {[key: string]: PetAttribute} 
}

interface Person {
    firstName: string
    lastName: string
    password: string
    addresses: PersonAddress[]
    pets: Pet[]
    phone?: string
}

describe('crypto manager', () => {
    it('should encrypt and decrypt an object', () => {
        const keyVal = Buffer.from('000102030405060708090a0b0c0d0e0f'+
                                   '101112131415161718191a1b1c1d1e1f'+
                                   '202122232425262728292a2b2c2d2e2f'+
                                   '303132333435363738393a3b3c3d3e3f', 'hex');

        const key = new Key('test-key', keyVal);
        const key2 = new Key('test-key2', keyVal);
        const keyring  = new InsecureKeyring(key, key2);

        const provider = new AeadAes256CbcHmacSha512Provider(keyring)
        const mgr = new DefaultCryptoManager()

        mgr.registerEncrypter('one', provider.encrypterForKey('test-key'))
        mgr.registerEncrypter('two', provider.encrypterForKey('test-key2'))
        mgr.defaultEncrypter(provider.encrypterForKey('test-key'))
        mgr.registerDecrypter(provider.decrypter())

        const schema = mgr.newCryptoSchema<Person>({
            fields: {
                'password': {
                    encryptionKey: 'one'
                },
                'addresses': {
                    fields: {
                        'houseName': {
                            encryptionKey: 'two'
                        },
                        'street': {
                            fields: {
                                'secondLine': {
                                    encryptionKey: 'one'
                                }
                            }
                        },
                        'attributes': {
                            fields: {
                                'action': {
                                    encryptionKey: 'one'
                                },
                            },
                        }
                    },
                    encryptionKey: 'one'
                },
                'pets': {
                    fields: {
                        'attributes': {
                            fields: {
                                'action': {
                                    encryptionKey: 'one'
                                },
                            },
                            encryptionKey: 'two'
                        }
                    },
                },
                'phone': {
                    encryptionKey: 'one'
                }
            }
        })

        const p1: Person = {
            firstName: 'Barry',
            lastName: 'Sheen',
            password: 'bang!',
            addresses: [
                {
                    houseName: 'my house',
                    street: [
                        {
                            firstLine: 'my street',
                            secondLine: 'my second line'
                        }
                    ]
                },
                {
                    houseName: 'my other house',
                    attributes: {
                        thing: {
                            action: 'action',
                            extra: 'extra'
                        }
                    }
                }
            ],
            pets: [
                 {
                    animal: 'dog',
                    attributes: {
                        tail: {
                            action: 'wags'
                        }
                    }
                },
                {
                    animal: 'cat',
                    attributes: {
                        claws: {
                            action: 'scratch'
                        }
                    }
                }
            ],
            phone: '123456'
        }
        const encrypted = schema.encrypt(p1)

        expect(encrypted.firstName).to.equal(p1.firstName)
        expect(encrypted.lastName).to.equal(p1.lastName)
        expect(encrypted['encrypted$password']).to.be.an('object')
        expect(encrypted['encrypted$addresses']).to.be.an('object')
        expect(encrypted['encrypted$phone']).to.be.an('object')
        expect(encrypted.pets.length).to.equal(2)
        expect(encrypted.pets[0].animal).to.equal(p1.pets[0].animal)
        expect(encrypted.pets[0]['encrypted$attributes']).to.be.an('object')
        expect(encrypted.pets[1].animal).to.equal(p1.pets[1].animal)
        expect(encrypted.pets[1]['encrypted$attributes']).to.be.an('object')

        const decrypted = schema.decrypt(encrypted)
        expect(decrypted).to.deep.equal(p1)
    })

    it('should mangle a field name', () => {
        const mgr = new DefaultCryptoManager()

        expect(mgr.mangle('field')).to.equal('encrypted$field')
    })

    it('should demangle a field name', () => {
        const mgr = new DefaultCryptoManager()

        expect(mgr.demangle('encrypted$field')).to.equal('field')
    })

    it('should detect a mangled field name', () => {
        const mgr = new DefaultCryptoManager()

        expect(mgr.isMangled('encrypted$field')).to.equal(true)
        expect(mgr.isMangled('field')).to.equal(false)
    })

    it('should mangle a field name with non default prefix', () => {
        const mgr = new DefaultCryptoManager({
            encryptedFieldPrefix: '__crypto_'
        })

        expect(mgr.mangle('field')).to.equal('__crypto_field')
    })

    it('should demangle a field name', () => {
        const mgr = new DefaultCryptoManager({
            encryptedFieldPrefix: '__crypto_'
        })

        expect(mgr.demangle('__crypto_field')).to.equal('field')
    })

    it('should detect a mangled field name', () => {
        const mgr = new DefaultCryptoManager({
            encryptedFieldPrefix: '__crypto_'
        })

        expect(mgr.isMangled('__crypto_field')).to.equal(true)
        expect(mgr.isMangled('field')).to.equal(false)
    })

    it('should throw decrypting with missing decrypter for algo', () => {
        const mgr = new DefaultCryptoManager()

        expect(() => mgr.decrypt(new EncryptionResult({
            alg: 'AEAD_AES_256_CBC_HMAC_SHA512',
            kid: 'test-key',
            ciphertext: 'GGvOMLcK5b/3YZpQJI0G8BLm98oj20ZLdqKDV3MfTuGlWL4RLzoaAtJihk='
        }))).to.throw()
    })

    it('should throw decrypting with missing encrypter for key', () => {
        const mgr = new DefaultCryptoManager()

        expect(() => mgr.decrypt(new EncryptionResult({
            alg: 'AEAD_AES_256_CBC_HMAC_SHA512',
            kid: 'test-key',
            ciphertext: 'GGvOMLcK5b/3YZpQJI0G8BLm98oj20ZLdqKDV3MfTuGlWL4RLzoaAtJihk='
        }))).to.throw()
    })
})