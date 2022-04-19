/*
 * Copyright (c) 2021 Couchbase, Inc.
 *
 * Use of this software is subject to the Couchbase Inc. Enterprise Subscription License Agreement
 * which may be found at https://www.couchbase.com/ESLA-11132015.
 */

import { KeyInvalidError } from './errors';


/**
 * The result of encrypting a field.
 */
export class EncryptionResult {
    /**
     * The underlying object for the result.
     */
    private _values: { [key: string]: string; } = {};

    /**
     * @internal
     */
    constructor(value: { [key: string]: string; }) {
        if (value.alg == undefined) {
            throw new Error("alg missing");
        }
        if (value.kid == undefined) {
            throw new KeyInvalidError();
        }
        if (value.ciphertext == undefined) {
            throw new Error("ciphertext missing");
        }

        this._values = value;
    }

    /**
     * The algorithm used to create this EncryptionResult.
     */
    algorithm(): string {
        return this._values["alg"];
    }

    /**
     * The kid of the key used to create this EncryptionResult.
     */
    kid(): string {
        return this._values["kid"];
    }

    /**
     * The cipher text value of the result of applying encryption to a field.
     */
    ciphertext(): string {
        return this._values["ciphertext"];
    }

    /**
     * Performs a lookup in the underlying result object.
     * Used for providing access to extra fields such as iv which was placed in the result in v1 of the library.
     *
     * @param key The key to lookup.
     */
    get(key: string): string | undefined {
        return this._values[key];
    }

    /**
     *  Converts the EncryptionResult into a plain object.
     */
    asMap(): { [key: string]: any; } {
        return this._values;
    }
}
