/*
 * Copyright (c) 2021 Couchbase, Inc.
 *
 * Use of this software is subject to the Couchbase Inc. Enterprise Subscription License Agreement
 * which may be found at https://www.couchbase.com/ESLA-11132015.
 */

import { IEncrypter, IDecrypter} from './crypto'
import { EncryptionResult } from "./encryptionresult"
import { IKeyring, IKey } from './keyring'
import {KeyInvalidError,InvalidCipherTextError, KeyNotFoundError} from './errors'
import * as crypto from 'crypto'

/**
 * An IEncrypter implementation which uses the AEAD_AES_256_CBC_HMAC_SHA512 algorithm to encrypt data.
 */
export class AeadAes256CbcHmacSha512Encypter implements IEncrypter {
    /**
     * The ID of the key used by the encrypter.
     */
    private _keyID: string
    /**
     * The provider used to create this encrypter.
     */
    private _provider: AeadAes256CbcHmacSha512Provider

    /**
     * @internal
     */
    constructor(provider: AeadAes256CbcHmacSha512Provider, keyID: string) {
        this._provider = provider
        this._keyID = keyID
    }

    /**
     * Applies the AEAD_AES_256_CBC_HMAC_SHA512 algorithm to to encrypt data.
     *
     * @param value The value to encrypt.
     */
    encrypt(value: any): EncryptionResult {
        const ciphertext = this._encrypt(Buffer.from(JSON.stringify(value), 'utf8'))
        return new EncryptionResult({alg: algorithm(), kid: this._keyID, ciphertext:ciphertext})
    }

    /**
     * @internal
     */
    encryptWithExtras(value:Buffer, iv:Buffer, assocData?: Buffer): EncryptionResult {
        const ciphertext = this._encrypt(value, iv, assocData)
        return new EncryptionResult({alg: algorithm(), kid: this._keyID, ciphertext:ciphertext})
    }

    /**
     * @internal
     */
    private _encrypt(value: Buffer, iv?: Buffer, associatedData?: Buffer): string {
        const key = this._provider.keyring().get(this._keyID)
        if (!key) {
            throw new KeyNotFoundError();
        }
        validateKeyLength(key)

        const hmacKey = key.value.slice(0, 32)
        const aesKey = key.value.slice(32)
        if (iv == undefined) {
            iv = crypto.randomBytes(16)
        }

        const cipher = crypto.createCipheriv("aes-256-cbc", aesKey, iv)
        const aesCipher = Buffer.concat([iv, cipher.update(value), cipher.final()])

        if (associatedData == undefined) {
            associatedData = Buffer.from('')
        }
        const assocLen = Buffer.allocUnsafe(8)
        assocLen.writeBigUInt64BE(BigInt(associatedData.length*8), 0)

        const digest = crypto.createHmac('sha512', hmacKey).update(associatedData).update(aesCipher).update(assocLen).digest()
        const sig = digest.slice(0, 32)

        return Buffer.concat([aesCipher, sig]).toString('base64')
    }
}

/**
 * An IDecrypter implementation which uses the AEAD_AES_256_CBC_HMAC_SHA512 algorithm to decrypt data.
 *
 */
export class AeadAes256CbcHmacSha512Decrypter implements IDecrypter {
    /**
     * The provider used to create this decrypter.
     */
    private _provider: AeadAes256CbcHmacSha512Provider

    /**
     * @internal
     */
    constructor(provider: AeadAes256CbcHmacSha512Provider) {
        this._provider = provider
    }

    /**
     * Returns the name of the algorithm used by this decrypter - AEAD_AES_256_CBC_HMAC_SHA512.
     * This is used by an ICryptoManager to select a decrypter based on an EncryptionResult.
     */
    algorithm(): string {
        return algorithm()
    }

    /**
     * Applies the AEAD_AES_256_CBC_HMAC_SHA512 algorithm to to decrypt data.
     *
     * @param value The EncryptionResult to decrypt.
     *
     */
    decrypt(value:EncryptionResult): any {
        const alg = value.algorithm()
        if (alg != this.algorithm()) {
            throw new Error("invalid algorithm")
        }

        const keyID = value.kid()
        if (!keyID) {
            throw new KeyInvalidError()
        }

        const key = this._provider.keyring().get(keyID)
        if (!key) {
            throw new KeyNotFoundError();
        }
        validateKeyLength(key)
        const ciphertext = Buffer.from(value.ciphertext(), 'base64')

        return JSON.parse(this._decrypt(key.value, ciphertext).toString())
    }

    /**
     * @internal
     */
    decryptWithExtras(value:EncryptionResult, assocData: Buffer): Buffer {
        const keyID = value.kid()
        const key = this._provider.keyring().get(keyID)
        validateKeyLength(key)
        const ciphertext = Buffer.from(value.ciphertext(), 'base64')

        return this._decrypt(key.value, ciphertext, assocData)
    }

    /**
     * @internal
     */
    private _decrypt(key: Buffer, ciphertext: Buffer, associatedData?: Buffer): Buffer {
        const aesKey = key.slice(32)
        const hmacKey = key.slice(0, 32)

        const aesCipher = ciphertext.slice(0, ciphertext.length - 32)
        const authTag = ciphertext.slice(ciphertext.length - 32)

        if (associatedData == undefined) {
            associatedData = Buffer.from('')
        }
        const assocLen = Buffer.allocUnsafe(8)
        assocLen.writeBigUInt64BE(BigInt(associatedData.length*8), 0)

        const digest = crypto.createHmac('sha512', hmacKey).update(associatedData).update(aesCipher).update(assocLen).digest()
        const sig = digest.slice(0, 32)

        if (sig.compare(authTag) !== 0) {
            throw new InvalidCipherTextError()
        }

        const iv = aesCipher.slice(0, 16)
        const data = aesCipher.slice(16)

        const decipher = crypto.createDecipheriv('aes-256-cbc', aesKey, iv)

        return Buffer.concat([decipher.update(data), decipher.final()])
    }
}

/**
 * Provides encrypters and decrypters for the AEAD_AES_256_CBC_HMAC_SHA512 algorithm.
 */
export class AeadAes256CbcHmacSha512Provider {
    /**
     * The keyring to use when looking up key IDs within encrypters and decrypters.
     */
    private _keyring: IKeyring

    /**
     * Creates a new AeadAes256CbcHmacSha512Provider.
     *
     * @param keyring The keyring to use when looking up key IDs within encrypters and decrypters.
     */
    constructor(keyring: IKeyring) {
        this._keyring = keyring
    }

    /**
     * Provides a new encrypter which will use the key ID provided.
     *
     * @param keyID The ID of the key to use for encryption.
     *
     */
    encrypterForKey(keyID: string): AeadAes256CbcHmacSha512Encypter {
        return new AeadAes256CbcHmacSha512Encypter(this, keyID)
    }

    /**
     * Provides a new decrypter for the AEAD_AES_256_CBC_HMAC_SHA512 algorithm.
     *
     */
    decrypter(): AeadAes256CbcHmacSha512Decrypter {
        return new AeadAes256CbcHmacSha512Decrypter(this)
    }

    /**
     * @internal
     */
    keyring(): IKeyring {
        return this._keyring
    }
}

/**
 * @internal
 */
function validateKeyLength(key: IKey) {
    if (key.value.byteLength == 64) {
        return
    }

    throw new KeyInvalidError()
}

/**
 * @internal
 */
function algorithm():string {
    return 'AEAD_AES_256_CBC_HMAC_SHA512'
}
