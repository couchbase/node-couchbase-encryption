# Couchbase Go SDK Encryption Extension #

This project contains the cryptographic algorithms and key store providers which are
used by the Couchbase Go SDK to provide field level encryption.


## Cryptography Support ##

The project supports the following cryptographic algorithms

* `AES-256`
* `RSA`

and the following key store providers

* `Insecure`

## Usage ##
Register the encryption libraries transcoder in place of the default SDK transcoder:
```javascript

```
