/*
 * Copyright (c) 2021 Couchbase, Inc.
 *
 * Use of this software is subject to the Couchbase Inc. Enterprise Subscription License Agreement
 * which may be found at https://www.couchbase.com/ESLA-11132015.
 */

/**
 * A generic base error that all errors inherit.
 */
export class CryptoError extends Error {
    /**
     * Specifies the underlying cause of this error, if one is available.
     */
    cause: Error | undefined

    constructor(message: string, cause?: Error) {
      super(message)
      this.name = this.constructor.name

      this.cause = cause
    }
}

/**
 * Indicates that a key could not be found for a given key ID.
 */
export class KeyNotFoundError extends CryptoError {

    constructor() {
        super('specified key was not found')
    }
}

/**
 * Indicates that a key is in some way invalid.
 */
export class KeyInvalidError extends CryptoError {

    constructor() {
        super('specified key is invalid')
    }
}

/**
 * Indicates the cipher text is not valid.
 */
export class InvalidCipherTextError extends CryptoError {

    constructor() {
        super('invalid ciphertext')
    }
}

/**
 * Indicates the encrypter specified in a crypto schema could not be found.
 */
export class EncrypterNotFoundError extends CryptoError {

    constructor() {
        super('encrypter not found')
    }
}

/**
 * Indicates the decrypter specified in an encrypted field block could not be found.
 */
export class DecrypterNotFoundError extends CryptoError {

    constructor() {
        super('decrypter not found')
    }
}

/**
 * Indicates the decrypter is already registered with the manager.
 */
export class DecrypterExistsError extends CryptoError {

    constructor() {
        super('decrypter already exists')
    }
}

/**
 * Indicates the encrypter is already registered with the manager.
 */
export class EncrypterExistsError extends CryptoError {

    constructor() {
        super('encrypter already exists')
    }
}