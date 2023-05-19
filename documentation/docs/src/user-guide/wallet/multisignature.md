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
--source [my-key1] \
--public-keys [my-key1,my-key2] \
--signers [my-key1,my-key2] \
--threshold 2
```


## Submitting a multisignature transaction
In order to submit a multisignature transaction, an offline transaction must first be constructed. 

### Constructing an offline transaction
The `--offline-tx` argument allows a user to do this. This can be done through the following method:
```bash
namadac transfer \
--source [my-multisig-alias] \
--target [some-established-account-alias] \
--token NAM \
--amount 100 \
--signers [my-key1] \
--offline-tx
```

```admonish note
The `--signers` argument is still required, despite the fact that the transaction is offline. This has no effect on the transaction, but means if it was a 1-of-n multisig, the user could submit the transaction immediately.
```

This will give some output similar to the following:
```bash
Transaction code, data and timestmamp have been written to files code.tx and data.tx.
You can share the following blob with the other signers:
3032baacfe6b87e2c59caa2ffa928924463dca2054df88575dec7cf6df865c5c01920000000028000000443439374537413946363031364438383632374239324436433642443843454545373645463138450028000000454244464534413936383236414536383032423733434339333444434245323933413245394330440028000000344238384642393133413037363645333041303042324642384141323934394137313045323445360000ca9a3b00000000000020000000323032332d30352d31395431303a33393a34372e3836303637342b30303a30301e0000006c6f63616c2e36646162326265336531303265383937356564643132373000

You can later submit the tx with:
namada client tx --code-path code.tx --data-path data.tx --timestamp 
2077-04-20T13:37:69.108000+00:00
```

What this means is that the transaction has been constructed, and is ready to be signed. 

There will be 2 files created in the current directory. One ending in `-code.tx` and another ending in `-data.tx`. For the purposes of this example, let's say these files are `a45ef98a817290d6fc0efbd480bf66647ea8061aee1628ce09b4af4f4eeed1c2-code.tx` and `a45ef98a817290d6fc0efbd480bf66647ea8061aee1628ce09b4af4f4eeed1c2-data.tx`. The first file contains the code for the transaction, and the second file contains the data for the transaction. The timestamp argument describes the time at which the transaction was created. This is important, as the signature is also computed over the timestamp, so should be saved.

### Signing the transaction

The next step is to sign the transaction. `my-key1` can sign the transaction through the following method:
```bash
namadac sign-tx \
--signing-tx 3032baacfe6b87e2c59caa2ffa928924463dca2054df88575dec7cf6df865c5c01920000000028000000443439374537413946363031364438383632374239324436433642443843454545373645463138450028000000454244464534413936383236414536383032423733434339333444434245323933413245394330440028000000344238384642393133413037363645333041303042324642384141323934394137313045323445360000ca9a3b00000000000020000000323032332d30352d31395431303a33393a34372e3836303637342b30303a30301e0000006c6f63616c2e36646162326265336531303265383937356564643132373000 \
--signers [my-key1]
```

```admonish note
Note that only one key could sign a transaction at a time. The `--signers` method does not accept multiple arguments in this instance
```

This will give some output similar to the following:
```bash
Signature has been serialized to 4821284c3ad966d615016c10fdcd64d848895b119b2c94812b8b65c949ac62d4-000ac93185f02fc69883392bb270b2f040c8219c255a7c24016f6a820ed6afe24f-signature.tx
```

Which means that the signature has been saved to this file (located in the current directory). 

Let's save this as an alias:
```bash
export SIGNATURE_ONE=4821284c3ad966d615016c10fdcd64d848895b119b2c94812b8b65c949ac62d4-000ac93185f02fc69883392bb270b2f040c8219c255a7c24016f6a820ed6afe24f-signature.tx
```

Ensure to sign the transaction with at least k-of-n keys, where k is the minimum number of signatures required to submit a transaction, and n is the total number of keys. In this example, k=2 and n=2.

Then let's say this signing produces another signature which we save to the alias `SIGNATURE_TWO`.

### Submitting the transaction

The final step is to submit the transaction. This can be done through the following method:
```bash
namadac tx \
--code-path a45ef98a817290d6fc0efbd480bf66647ea8061aee1628ce09b4af4f4eeed1c2-code.tx \
--data-path a45ef98a817290d6fc0efbd480bf66647ea8061aee1628ce09b4af4f4eeed1c2-data.tx \
--timestamp 2077-04-20T13:37:69.108000+00:00 \
--signatures $SIGNATURE_ONE $SIGNATURE_TWO \
--signers [my-key1]
```

```admonish note
1. Note the lack of commas used in the `--signatures` argument. This is because the argument is a list of files, not a list of signatures.
2. The `--signers` argument is still required, despite the fact that the transaction is already signed. 
```

## Changing the multisig threshold
It is possible to change the multisig threshold of an account. This can be done through the following method:
```bash
namadac update \
--address [my-multisig-address] \
--threshold 1 \
--signers [my-key1,my-key2]
```

One can check that the threshold has been updated correctly by running:
```bash
namadac query-account \
--address [my-multisig-address]
```
Which will yield the threshold of 1, together with the two public keys.

## Changing the public keys of a multisig account
It is possible to change the public keys of a multisig account. This can be done through the following method:
```bash
namadac update \
--address [my-multisig-address] \
--public-keys [my-key3,my-key4,my-key5] \
--signers [my-key1,my-key2]
```

Which will change the public keys of the multisig account from `my-key1` and `my-key2` to the keys `my-key3`, `my-key4` and `my-key5` (assuming they exist in the wallet).

The public-keys provided to the argument `--public-keys` will become the new signers of the multisig. The list must be a list of public keys, separated by commas, and without spaces. There must be at least 1 public key in the list, and the length of list must be at least the threshold of the multisig account.