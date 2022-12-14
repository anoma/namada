# Starter genesis templates

This directory contains genesis templates for a minimum configuration with a single token account, which can be used as a starter for setting up a new chain.

If you're modifying any of the files here, you can run this to ensure that the changes are valid:

```shell
cargo watch -x "test test_validate_starter_genesis_templates"
```

In order to be able to run it, the following has to be added:

1. At least one key with a positive native [token balance](#token-balances)
2. At least one [validator account](#validator-accounts), with some native tokens transferred from the key, some of which have to be self-bonded in PoS to amount to a positive voting power

## Token balances

We'll generate a key and give it some token balance.

To generate a new key in a pre-genesis wallet (before the chain is setup), you can use e.g.:

```shell
namada wallet key gen --pre-genesis --alias "my-key"
```

This will print your public key:

```shell
Successfully added a key and an address with alias: "my-key".
Public key: pktest1qz5ywdn47sdm8s7rkzjl5dud0k9c9ndd5agn4gu0u0ryrmtmyuxmk948q0p
```

The public key can then be given some tokens in the [balances.toml file](balances.toml) with e.g.:

```toml
[token.NAM]
pktest1qz5ywdn47sdm8s7rkzjl5dud0k9c9ndd5agn4gu0u0ryrmtmyuxmk948q0p = 1_337_707.50
```

## Validator accounts

For this step, you'll need to have a key with some native [token balance](#token-balances), from which you can sign the validator account creation genesis transaction.

To generate a new validator pre-genesis wallet and produce signed transactions with it, use e.g.:

```shell
namada client utils \
  init-genesis-validator \
  --source "my-key" \
  --alias "my-validator" \
  --net-address "127.0.0.1:26656" \
  --commission-rate 0.05 \
  --max-commission-rate-change 0.01 \
  --transfer-from-source-amount 1_337_707.50 \
  --self-bond-amount 1_000_000
```

This will print the validator transactions that can be added to the [transactions.toml file](transactions.toml).

## Initialize the chain

This is sufficient minimal configuration to initialize the chain with the single genesis validator. All that's left is to pick a chain ID prefix and genesis time:

```shell
namada client utils \
  init-network \
  --chain-prefix "my-chain" \
  --genesis-time "2021-12-31T00:00:00Z" \
  --templates-path "path/to/templates" \
  --wasm-checksums-path "path/to/wasm/checksums.json"
```
