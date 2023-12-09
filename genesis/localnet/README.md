# Localnet genesis templates

This directory contains genesis templates for a local network with a single validator. The `src` directory contains generated pre-genesis wallet pre-loaded with unencrypted keys and a single validator `validator-0` wallet that are being used in the templates.

If you're modifying any of the files here, you can run this to ensure that the changes are valid:

```shell
cargo watch -x "test test_validate_localnet_genesis_templates"
```

The pre-genesis balances wallet is located at [pre-genesis/wallet.toml](pre-genesis/wallet.toml) and can be re-generated from the repo's root dir with:

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
  --alias validator-0-account-key --unsafe-dont-encrypt
cargo run --bin namadaw -- --base-dir "genesis/localnet/src" key gen \
  --alias faucet-key --unsafe-dont-encrypt
```

Some keys are used to setup established accounts and some are directly assigned balances in the [balances.toml](#balancestoml) file to implicit addresses derived from these keys.

## transactions.toml

### Transaction to initialize an established account

For example, Albert's account is created with:

```shell
cargo run --bin namadac -- --base-dir "genesis/localnet/src" utils \
  init-genesis-established-account \
  --path "genesis/localnet/src/pre-genesis/established/established-account-tx-albert.toml" \
  --aliases "albert-key"
```

Note that the command will print out your `Derived established account address`.

### Validator transactions

To create a validator's account, first initialize an established account:

```shell
cargo run --bin namadac -- --base-dir "genesis/localnet/src" utils \
  init-genesis-established-account \
  --path "genesis/localnet/src/pre-genesis/validator-0/unsigned-transactions.toml" \
  --aliases "validator-0-account-key"
```

The `Derived established account address` and the transaction added to the TOML file from this command is used in the following command.

The pre-genesis validator wallet used to generate [validator transactions for transactions.toml](src/pre-genesis/validator-0/transactions.toml) is located at [src/pre-genesis/validator-0/validator-wallet.toml](src/pre-genesis/validator-0/validator-wallet.toml) and can be re-generated:

```shell
cargo run --bin namadac -- --base-dir "genesis/localnet/src" utils \
  init-genesis-validator \
  --alias validator-0 \
  --address tnam1q9vhfdur7gadtwx4r223agpal0fvlqhywylf2mzx \
  --path "genesis/localnet/src/pre-genesis/validator-0/unsigned-transactions.toml" \
  --net-address "127.0.0.1:27656" \
  --commission-rate 0.05 \
  --max-commission-rate-change 0.01 \
  --email "null@null.net" \
  --self-bond-amount 100000 \
  --unsafe-dont-encrypt
```

### Delegations

A delegation with e.g. 20 000 NAM tokens to a validator account whose address has to be known beforehand (here the validator-0 created above) is created with:

```shell
cargo run --bin namadac -- --base-dir "genesis/localnet/src" utils \
  genesis-bond \
  --validator tnam1q9vhfdur7gadtwx4r223agpal0fvlqhywylf2mzx \
  --amount 20000 \
  --path "genesis/localnet/src/pre-genesis/bond/bond-tx-albert.toml"
```

### Signing

The non-validator transactions are manually appended together in [src/pre-genesis/unsigned-transactions.toml](src/pre-genesis/unsigned-transactions.toml) and then signed to produce [src/pre-genesis/signed-transactions.toml](src/pre-genesis/signed-transactions.toml) using:

```shell
cargo run --bin namadac -- --base-dir "genesis/localnet/src" utils \
  sign-genesis-txs \
  --path "genesis/localnet/src/pre-genesis/unsigned-transactions.toml" \
  --output "genesis/localnet/src/pre-genesis/signed-transactions.toml"
```

The validator transactions are signed using (note the extra `--alias` argument needed to find the validator pre-genesis wallet):

```shell
cargo run --bin namadac -- --base-dir "genesis/localnet/src" utils \
  sign-genesis-txs \
  --path "genesis/localnet/src/pre-genesis/validator-0/unsigned-transactions.toml" \
  --output "genesis/localnet/src/validator-0/signed-transactions.toml"
  --alias validator-0
```

This non-validator [src/pre-genesis/signed-transactions.toml](src/pre-genesis/signed-transactions.toml) are joined together with [src/validator-0/signed-transactions.toml](src/validator-0/signed-transactions.toml) in [transactions.toml](transactions.toml).

## balances.toml

The [balances.toml file](balances.toml) contains token balances associated with public keys or established addresses which can be derived from genesis transactions. The public keys from the wallet can be found with:

```shell
cargo run --bin namadaw -- --base-dir "genesis/localnet/src" key list
```

If you didn't note the address from your transactions, you can deterministically derive an established address from the TOML file again, run with the `--path` set to a transaction TOML file:

```shell
cargo run --bin namadac -- --base-dir "genesis/localnet/src" utils \
  derive-genesis-addresses \
  --path "genesis/localnet/src/pre-genesis/established/established-account-tx-validator-0.toml"
```

## Validation

A unit test `test_validate_localnet_genesis_templates` is setup to check validity of the localnet setup.
