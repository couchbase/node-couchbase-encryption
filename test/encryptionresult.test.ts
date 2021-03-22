import { expect } from "chai";
import { EncryptionResult } from '../lib/encryptionresult'


describe('EncryptionResult', () => {
    it('should correctly handle kid, alg, and ciphertext', () => {
        const expected = {
            alg: "myalg",
            kid: "mykid",
            ciphertext: "mycipher"
        }
        const result = new EncryptionResult(expected)

        expect(result.algorithm()).to.equal(expected.alg)
        expect(result.kid()).to.equal(expected.kid)
        expect(result.ciphertext()).to.equal(expected.ciphertext)
    })

    it('should correctly store additional fields', () => {
        const expected = {
            alg: "myalg",
            kid: "mykid",
            ciphertext: "mycipher",
            iv: "myiv",
        }
        const result = new EncryptionResult(expected)

        expect(result.get("iv")).to.equal(expected.iv)
    })

    it('should throw on missing alg', () => {
        const expected = {
            kid: "mykid",
            ciphertext: "mycipher"
        }
        expect(() => new EncryptionResult(expected)).to.throw()
    })

    it('should throw on missing kid', () => {
        const expected = {
            alg: "myalg",
            ciphertext: "mycipher"
        }
        expect(() => new EncryptionResult(expected)).to.throw()
    })

    it('should throw on missing ciphertext', () => {
        const expected = {
            alg: "myalg",
            kid: "mykid"
        }
        expect(() => new EncryptionResult(expected)).to.throw()
    })
})