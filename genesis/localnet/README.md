# Localnet genesis templates

This directory contains genesis templates for a local network with a single validator, together with a pre-genesis wallet with some keys.

The pre-genesis wallet is located at [pre-genesis/wallet.toml](pre-genesis/wallet.toml) and can be re-generated from the repo's root dir with:

```shell
cargo run --bin namadaw -- --base-dir "genesis/localnet" key gen --alias albert_key --unsafe-dont-encrypt
cargo run --bin namadaw -- --base-dir "genesis/localnet" key gen --alias bertha_key --unsafe-dont-encrypt
cargo run --bin namadaw -- --base-dir "genesis/localnet" key gen --alias christel_key --unsafe-dont-encrypt
cargo run --bin namadaw -- --base-dir "genesis/localnet" key gen --alias daewon --unsafe-dont-encrypt
cargo run --bin namadaw -- --base-dir "genesis/localnet" key gen --alias validator_key --unsafe-dont-encrypt
```

A unit test `test_localnet_genesis_templates` is setup to check validity of this template.

The [balances.toml file](balances.toml) contains token balances associated with the public keys. The public keys from the wallet can be found with:

```shell
cargo run --bin namadaw -- --base-dir "genesis/localnet" key list
```
