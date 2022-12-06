# Cryptographic schemes

Namada currently supports both Ed25519 and Secp256k1 (currently in [development](https://github.com/anoma/namada/pulls/278)) for signing transactions or any other arbitrary data, with support for more signature schemes to be added:

- [`Sr25519`](https://github.com/anoma/namada/issues/646)

The implementation of the Ed25519 scheme makes use of the `ed25519_consensus` crate, while the `libsecp256k1` crate is used for Secp256k1 keys.

## Public keys

A public key is a [Borsh encoded](encoding.md) `PublicKey`.

## Secret Keys

A secret key is a [Borsh encoded](encoding.md) `SecretKey`. In order to prevent leaks of sensitive information, the contents of a secret key are zeroized. Sometimes the Rust compiler can optimize away the action of zeroing the bytes of data corresponding to an object dropped from scope. For secret keys, this data in memory is directly zeroed after the keys are no longer needed.

## Signatures

A signature in Namada is a [Borsh encoded](encoding.md) `Signature`.
