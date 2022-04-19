/*
 * Copyright (c) 2021 Couchbase, Inc.
 *
 * Use of this software is subject to the Couchbase Inc. Enterprise Subscription License Agreement
 * which may be found at https://www.couchbase.com/ESLA-11132015.
 */

import { IDecrypter } from "./crypto";
import { EncryptionResult } from "./encryptionresult";
import { IKeyring } from "./keyring";
import * as crypto from 'crypto';
import { InvalidCipherTextError, KeyInvalidError, KeyNotFoundError } from "./errors";

/**
 * An IDecrypter implementation which uses the AES-256-HMAC-SHA256 algorithm to decrypt data.
 * This decrypter is intended to be used for support of legacy data created using v1 of the library.
 */
export class LegacyAes256Decrypter implements IDecrypter {
    /**
     * The keyring to use when looking up key IDs.
     */
    private _keyring: IKeyring;
    /**
     * Given a public ID provides a private key ID. This function allows a single decrypter to support many keys.
     */
    private _keyFn: (publicKey: string)=>string;

    /**
     * Creates a new LegacyAes256Decrypter.
     *
     * @param keyring The keyring to use for looking up keys.
     * @param keyFn Given a public ID provides a private key ID. This function allows a single decrypter to support many keys.
     */
    constructor(keyring: IKeyring, keyFn: (publicKey: string)=>string) {
        this._keyring = keyring;
        this._keyFn = keyFn;
    }

    /**
     * Returns the name of the algorithm used by this decrypter - AES-256-HMAC-SHA256.
     * This is used by an ICryptoManager to select a decrypter based on an EncryptionResult.
     */
    algorithm(): string {
        return 'AES-256-HMAC-SHA256';
    }

    /**
     * Applies the AES-256-HMAC-SHA256 algorithm to to decrypt data.
     *
     * @param value The EncryptionResult to decrypt.
     *
     */
    decrypt(value:EncryptionResult): any {
        return this._decrypt(value);
    }

    /**
     * @Internal
     */
    private _decrypt(result:EncryptionResult): any {
        const alg = result.algorithm()
        if (alg != this.algorithm()) {
            throw new Error("invalid algorithm")
        }
        const kid = result.kid()
        if (!kid) {
            throw new KeyInvalidError()
        }
        const key = this._keyring.get(kid);
        if (!key) {
            throw new KeyNotFoundError();
        }

        const hmacKeyID = this._keyFn(key.id);
        const hmacKey = this._keyring.get(hmacKeyID);
        if (!hmacKey) {
            throw new KeyNotFoundError();
        }

        const ivCoded = result.get("iv");
        if (!ivCoded) {
            throw new Error("data missing iv");
        }

        const sigData =
            key.id +
            this.algorithm() +
            ivCoded +
            result.ciphertext();

        const sig = crypto.createHmac('sha256', hmacKey.value).update(sigData).digest('base64');

        const resultSig = result.get("sig");
        if (!resultSig) {
            throw new Error("data missing sig");
        }
        if (sig !== resultSig) {
          throw new InvalidCipherTextError();
        }

        const iv = Buffer.from(ivCoded, 'base64');

        const decipher = crypto.createDecipheriv('aes-256-cbc', key.value, iv);

        const decrypted = decipher.update(result.ciphertext(), 'base64', 'utf8') +
            decipher.final('utf8');

        return JSON.parse(decrypted);
    }
}
