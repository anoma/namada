# Localnet genesis templates

This directory contains genesis templates for a local network with a single validator. The `src` directory contains generated pre-genesis wallet pre-loaded with unencrypted keys and a single validator `"validator-0" wallet that are being used in the templates.

If you're modifying any of the files here, you can run this to ensure that the changes are valid:

```shell
cargo watch -x "test test_validate_localnet_genesis_templates"
```

## balances.toml

The pre-genesis balances wallet is located at [pre-genesis/wallet.toml](pre-genesis/wallet.toml) was used to setup the [balances.toml](balances.toml) and can be re-generated from the repo's root dir with:

```shell
cargo run --bin namadaw -- --base-dir "genesis/localnet/src" key gen \
  --alias albert-key --unsafe-dont-encrypt
cargo run --bin namadaw -- --base-dir "genesis/localnet/src" key gen \
  --alias bertha-key --unsafe-dont-encrypt
cargo run --bin namadaw -- --base-dir "genesis/localnet/src" key gen \
  --alias christel --unsafe-dont-encrypt
cargo run --bin namadaw -- --base-dir "genesis/localnet/src" key gen \
  --alias daewon --unsafe-dont-encrypt
cargo run --bin namadaw -- --base-dir "genesis/localnet/src" key gen \
  --alias validator-0-key --unsafe-dont-encrypt
cargo run --bin namadaw -- --base-dir "genesis/localnet/src" key gen \
  --alias faucet-key --unsafe-dont-encrypt
```

The [balances.toml file](balances.toml) contains token balances associated with the public keys. The public keys from the wallet can be found with:

```shell
cargo run --bin namadaw -- --base-dir "genesis/localnet/src" key list
```

## transactions.toml

The pre-genesis validator wallet used to generate [validator transactions for transactions.toml](src/pre-genesis/validator-0/transactions.toml) is located at [src/pre-genesis/validator-0/wallet.toml](src/pre-genesis/validator-0/wallet.toml) and can be re-generated from the repo's root dir with:

```shell
cargo run --bin namadac -- --base-dir "genesis/localnet/src" utils \
  init-genesis-validator \
  --source validator-0-key \
  --alias validator-0 \
  --net-address "127.0.0.1:27656" \
  --commission-rate 0.05 \
  --max-commission-rate-change 0.01 \
  --transfer-from-source-amount 1_000_000_000 \
  --self-bond-amount 900_000_000 \
  --unsafe-dont-encrypt
```

The rest of the transactions are generated from [src/pre-genesis/unsigned-transactions.toml](src/pre-genesis/unsigned-transactions.toml) using:

```shell
cargo run --bin namadac -- --base-dir "genesis/localnet/src" utils \
  sign-genesis-tx \
  --path "genesis/localnet/src/pre-genesis/unsigned-transactions.toml" \
  --output "genesis/localnet/src/pre-genesis/signed-transactions.toml"
```

This command produces [src/pre-genesis/signed-transactions.toml](src/pre-genesis/signed-transactions.toml), which is then concatenated in [transactions.toml](transactiosn.toml) with the validator transactions.

## Validation

A unit test `test_localnet_genesis_templates` is setup to check validity of the localnet setup.
