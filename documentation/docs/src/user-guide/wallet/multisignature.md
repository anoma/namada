# Multisignature accounts on Namada

Multisignature accounts (multisigs) are accounts on Namada that allow for multiple signers. There are many benefits of having multisigs, including but not limited to 

- Increased security
- Ability to share wallets
- Better recovery options

For this reason, all accounts on Namada are multisignature accounts by default.

## Initialising a multisignature account

Before creating an account, a user must generate at least one cryptographic `key`, that will be used to sign transactions.

The following method will generate such a key:
```bash
namadaw key gen \
--alias my-key1
```
A second key can be generated as well (which will be useful for multisigs):
```bash
namadaw key gen \
--alias my-key2
```

An implicit address can also be generated:
```bash
namadaw address gen \
--alias my-address
```

Accounts on Namada are initialised through the following method:

**Non-multisig account (single signer)**
```bash
namadac init-account \
--alias [my-multisig-alias] \
--source [my-key1] \
--signers [my-key1]
```

**Multisig account (at leat 2 signers)**
```bash
namadac init-account \
--alias [my-multisig-alias] \
--source [my-key] \
--signers [my-key]
```
