/*
 * Copyright (c) 2021 Couchbase, Inc.
 *
 * Use of this software is subject to the Couchbase Inc. Enterprise Subscription License Agreement
 * which may be found at https://www.couchbase.com/ESLA-11132015.
 */

/**
 * The representation of a key within the library.
 */
export interface IKey {
    /**
     * The ID of this key.
     */
    id: string;
    /**
     * The value for this key.
     */
    value: Buffer;
}

/**
 * Stores keys and allows lookups.
 */
export interface IKeyring {
    /**
     * Gets a key from the keyring.
     *
     * @param keyID The ID of the key to get.
     */
    get(keyID: string): IKey;
}

    /**
     * Used for encrypting and decrypting data.
     */
export class Key {
    /**
     * The ID of this key.
     */
    id: string;
    /**
     * The value for this key.
     */
    value: Buffer;

    /**
     * Creates a new Key.
     *
     * @param id The ID of this key.
     * @param value The value for this key.
     */
    constructor(id: string, value:Buffer) {
        this.id = id;
        this.value = value;
    }
}

/**
 * An IKeyring interface which lives in memory and provides no security.
 *
 * DO NOT USE THIS IN PRODUCTION OR ANYWHERE YOU CARE ABOUT YOUR SECURITY.
 */
export class InsecureKeyring implements IKeyring {
    /**
     * The keys held by the keyring.
     */
    private _keys: {[keyID: string]: IKey} = {};

    /**
     * Creates a new InsecureKeyring.
     *
     * @param {...any} keys Initial set of keys stored in this keyring.
     */
    constructor(...keys: IKey[]) {
        for (const key of keys) {
            this._keys[key.id] = key
        }
    }

    /**
     * Gets a key from the keyring.
     *
     * @param keyID The ID of the key to get.
     */
    get(keyID: string): IKey {
        return this._keys[keyID];
    }
}