# An introduction to Namada Addresses
The purpose of the Namada wallet is to provide a user-interface to store and manage both keys and addresses. In this context, keys are (potentially) very large integers that have some meaning on an eliptic curve. Keys are the fundamental building blocks for accounts on Namada. Keys come in the form of *pairs* (secret and public), can be used to derive the **account address** (first 40 chars of the SHA256 hash of the public key).


All accounts in Namada have a unique address, exactly one Validity Predicate and optionally any additional data in its dynamic storage sub-space.

There are currently 3 types of account addresses:
- **Implicit *(not fully supported yet)*:** An implicit account is derived from your keypair and can be used to authorize certain transactions from the account. They can be used as recipients of transactions even if the account has not been used on-chain before.
- **Established:** Used for accounts that allow the deployment of custom validation logic. These must be created on-chain via a transaction (e.g. [initialize an account](./send-and-receive-nam-tokens.md). The address is generated on-chain and is not known until the transaction is applied (the user provides randomness).
- **Internal:** Special internal accounts, such as protocol parameters account, PoS and IBC.

## Manage keypairs

Namada uses [ed25519](https://en.wikipedia.org/wiki/EdDSA#Ed25519) keypairs for signing cryptographic operations on the blockchain.

To manage your keys, various sub-commands are available under:

```shell
namada wallet key
```

### Generate a keypair

It is possible to generate keys using the CLI. By doing so, an implicit account address is also derived in the process and added to storage.

```shell
namada wallet key gen --alias my-key
```

```admonish note
The derived implicit address shares the same `my-key` alias. The previous command has the same effect as `namada wallet address gen --alias my-key`.
```

### List all known keys

```shell
namada wallet key list
```

## Manage addresses


To manage addresses, similar to keys, various sub-commands are available:

```shell
namada wallet address
```

### Generate an implicit address

```shell
namada wallet address gen --alias my-account
```

```admonish note

Note that this will also generate and save a key from which the address was derived and save it under the same `my-account` alias. Thus, this command has the same effect as `namada wallet key gen --alias my-account`.
```

### List all known addresses

```shell
namada wallet address list
```