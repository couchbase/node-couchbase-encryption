/*
 * Copyright (c) 2021 Couchbase, Inc.
 *
 * Use of this software is subject to the Couchbase Inc. Enterprise Subscription License Agreement
 * which may be found at https://www.couchbase.com/ESLA-11132015.
 */

import { EncryptionResult } from './encryptionresult'
import { DecrypterExistsError, DecrypterNotFoundError, EncrypterExistsError, EncrypterNotFoundError } from './errors'

/**
 * Called from the CryptoManager to apply decryption to individual field values.
 * The algorithm is used by the CryptoManager to determine which decrypter to use
 * for a given EncryptionResult.
 */
export interface IDecrypter {
    /**
     * Returns the algorithm this decrypter can be used for.
     */
    algorithm(): string

    /**
     * Given an EncryptionResult will apply decryption and return the JSON value.
     *
     * @param result The encryption result to decrypt.
     */
    decrypt(result: EncryptionResult): any
}

/**
 * Called from the CryptoManager to apply encryption to individual field values.
 */
export interface IEncrypter {
    /**
     * Given a value will apply encryption and return an EncryptionResult.
     *
     * @param value The value to encrypt.
     */
    encrypt(value: any): EncryptionResult
}

/**
 * Responsible for management of encryption and decryption of data.
 */
export interface ICryptoManager{
    /**
     * Will use the encrypterAlias to lookup an encrypter and use it to encrypt the given value.
     *
     * @param value The value to encrypt.
     * @param encrypterAlias The alias to use to select an encrypter.
     */
    encrypt(value: any, encrypterAlias: string): {[key: string]: any}

    /**
     * Using the alg field within the EncryptionResult will lookup a decrypter and use it to decrypt the given value.
     *
     * @param result The encryption result to decrypt.
     */
	decrypt(result: EncryptionResult): any

    /**
     * Applies the encryption field prefix to the field name: e.g. Will turn myfield into encrypted$myfield.
     *
     * @param fieldName The field name to mangle.
     */
	mangle(fieldName: string): string

    /**
     * Removes the encryption field prefix from the field name: e.g. Will turn encrypted$myfield into myfield.
     *
     * @param fieldName The field name to demangle.
     */
	demangle(fieldName: string): string

    /**
     * Determines if the field name is prefixed with the encryption field prefix: e.g. Encrypted$myfield will return true.
     *
     * @param fieldName The field name to check if it is mangled.
     */
	isMangled(fieldName: string): boolean
}

/**
 * An individual field within a schema.
 * This object can contain more fields and/or an encryption key.
 * If an encryption key is set then it signal to encrypt this field once any nested fields that need encryption have been encrypted.
 */
export interface CryptoSchemaFieldBlock {
    /**
     * The encryption key to use to encrypt this field.
     */
    encryptionKey?: string
    /**
     * The set of fields that should either be encrypted or contain a tree containing a field to be encrypted.
     */
    fields?: {[key: string]: CryptoSchemaFieldBlock}
}

/**
 * The top level object of a CryptoSchema.
 */
export interface CryptoSchemaBlock {
    /**
     * The set of fields that should either be encrypted or contain a tree containing a field to be encrypted.
     */
    fields: {[key: string]: CryptoSchemaFieldBlock}
}

/**
 *  CryptoSchema is used to register which fields to apply encryption to for a type.
 */
export class CryptoSchema<T = any> {
    /**
     * The schema to apply to any values.
     */
    private _schema: CryptoSchemaBlock
    /**
     * The manager used to create this schema.
     */
    private _mgr: ICryptoManager

    /**
     * @Internal
     */
    constructor(mgr: ICryptoManager, schema: CryptoSchemaBlock) {
        this._mgr = mgr
        this._schema = schema
    }

    /**
     * Applies encryption to fields within an object based on the schema.
     *
     * @param val The object containing fields to encrypt.
     */
    encrypt(val: T): any {
        return this._encrypt(val, this._schema.fields)
    }

    /**
     * @Internal
     */
    private _encrypt(val: any, fields: {[key: string]: CryptoSchemaFieldBlock}): any {
        if (Array.isArray(val)) {
            const newArr: any[] = []
            for (let i = 0; i < val.length; i++) {
                newArr[i] = this._encrypt(val[i], fields)
            }
            return newArr
        } else if (typeof(val) === "object") {
            const newObj: {[key: string]: any} = {}
            for (const [fieldName, value] of Object.entries(val)) {
                const field = fields[fieldName]
                if (field) {
                    if (field.fields) {
                        newObj[fieldName] = this._encrypt(val[fieldName], field.fields)
                    }
                    if (field.encryptionKey !== undefined) {
                        if (val[fieldName]) {
                            newObj[this._mgr.mangle(fieldName)] = this._mgr.encrypt(val[fieldName], field.encryptionKey)
                            delete(newObj[fieldName])
                        }
                    }
                } else {
                    newObj[fieldName] = value
                }
            }
            return newObj
        }
    }

    /**
     * Applies decryption to fields within an object, based on a combination of the schema and the object fields.
     *
     * @param val The object containing fields to decrypt.
     * 
     */
    decrypt(val: any): T {
        return this._decrypt(val, this._schema.fields)
    }

    /**
     * @Internal
     */
    private _decrypt(val: any, fields: {[key: string]: CryptoSchemaFieldBlock}): any {
        if (Array.isArray(val)) {
            const newArr: any[] = []
            for (let i = 0; i < val.length; i++) {
                newArr[i] = this._decrypt(val[i], fields)
            }
            return newArr
        } else if (typeof(val) === "object") {
            const newObj: {[key: string]: any} = {}
            for (const [fieldName, value] of Object.entries(val)) {
                const field = fields[this._mgr.demangle(fieldName)]
                if (field) {
                    if (field.fields) {
                        newObj[fieldName] = this._decrypt(val[fieldName], field.fields)
                    }
                    if (field.encryptionKey !== undefined) {
                        if (val[fieldName]) {
                            newObj[this._mgr.demangle(fieldName)] = this._mgr.decrypt(new EncryptionResult(val[fieldName]))
                            delete(newObj[fieldName])
                        }
                    }
                } else {
                    newObj[fieldName] = value
                }
            }
            return newObj
        }
    }
}

/**
 * Options for configuring the DefaultCryptoManager.
 */
export interface DefaultCryptoManagerOptions {
    /**
     * Override "encrypted$" as the default field prefix.
     * For example to read values created by v1 of the library set this to __crypt_.
     */
    encryptedFieldPrefix?: string
}

/**
 * Default implementation of ICryptoManager providing a way to register encrypters and decrypters and
 * create CryptoSchemas.
 */
export class DefaultCryptoManager {
    /**
     * The name to prefix encrypted fields with.
     */
    private _encryptedFieldPrefix: string
    /**
     * The encrypters registered.
     */
    private _encrypters: {[key: string]: IEncrypter} = {}
    /**
     * The decrypters registered.
     */
    private _decrypters: {[key: string]: IDecrypter} = {}
    /**
     * The alias to use for the default encrypter.
     */
    private _defaultEncrypterAlias = "__DEFAULT__"


    /**
     * Creates a new DefaultCryptoManager.
     *
     * @param options The options for configuring the DefaultCryptoManager.
     */
    constructor(options?: DefaultCryptoManagerOptions) {
        if (!options) {
            options = {}
        }

        if (options.encryptedFieldPrefix) {
            this._encryptedFieldPrefix = options.encryptedFieldPrefix
        } else {
            this._encryptedFieldPrefix = "encrypted$"
        }
    }

    /**
     *
     * Registers a new encrypter with the manager.
     *
     * @param alias The alias to use for the encrypter.
     * @param encrypter The encrypter to register.
     */
    registerEncrypter(alias: string, encrypter: IEncrypter): void {
        if (this._encrypters[alias]) {
            throw new EncrypterExistsError()
        }
        this._encrypters[alias] = encrypter
    }

    /**
     *
     * Registers a default encrypter with the manager, to be used when alias is given but the field is flagged for encryption.
     *
     * @param encrypter The encrypter to register.
     */
    defaultEncrypter(encrypter: IEncrypter): void {
        if (this._encrypters[this._defaultEncrypterAlias]) {
            throw new EncrypterExistsError()
        }
        this._encrypters[this._defaultEncrypterAlias] = encrypter
    }

    /**
     *
     * Registers a new decrypter with the manager.
     *
     * @param decrypter The decrypter to register.
     */
    registerDecrypter(decrypter: IDecrypter): void {
        if (this._decrypters[decrypter.algorithm()]) {
            throw new DecrypterExistsError()
        }
        this._decrypters[decrypter.algorithm()] = decrypter
    }

    /**
     *
     *  Creates a new crypto schema which can be used to apply encryption to an object.
     *
     * @param schema The schema to create a new CryptoSchema for.
     */
    newCryptoSchema<T>(schema: CryptoSchemaBlock): CryptoSchema<T> {
        return new CryptoSchema<T>(this, schema)
    }

    /**
     *
     * Applies encryption to the given value based on the alias provided.
     *
     * @param value The value to encrypt.
     * @param encrypterAlias The alias of the encrypter to use for encryption.
     *
     */
    encrypt(value: any, encrypterAlias:string): {[key: string]: any} {
        if (encrypterAlias === '') {
            encrypterAlias = this._defaultEncrypterAlias
        }

        const encrypter  = this._encrypters[encrypterAlias]
        if (!encrypter) {
            throw new EncrypterNotFoundError()
        }

        return encrypter.encrypt(value).asMap()
    }

    /**
     *
     * Applies decryption to the EncryptionResult.
     * The decrypter used is derived from the alg field within the result itself.
     *
     * @param value The value to decrypt.
     *
     */
    decrypt(value: EncryptionResult): any {
        const algo = value.algorithm()
        if (!algo) {
            throw new Error("algorithm not found")
        }

        const decrypter = this._decrypters[algo]
        if (!decrypter) {
            throw new DecrypterNotFoundError()
        }

        return decrypter.decrypt(value)
    }

    /**
     *
     * Prefixes a field with the encryption field prefix.
     *
     * @param field The field name to mangle.
     *
     */
    mangle(field:string): string {
        return `${this._encryptedFieldPrefix}${field}`
    }

    /**
     *
     * Removes the encryption field prefix from a field.
     *
     * @param field The field name to demangle.
     *
     */
    demangle(field:string): string {
        return field.replace(this._encryptedFieldPrefix, '')
    }

    /**
     *
     * Checks whether a field is prefixed with the encryption field prefix.
     *
     * @param field The field name to check if is mangled.
     *
     */
    isMangled(field:string): boolean {
        return field.startsWith(this._encryptedFieldPrefix)
    }
}

