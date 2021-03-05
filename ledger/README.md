# Anoma ledger prototype

## Quick start

The ledger currently requires that [Tendermint version 0.34.x](https://github.com/tendermint/tendermint) is installed and available on path. [The pre-built binaries and the source for 0.34.8 are here](https://github.com/tendermint/tendermint/releases/tag/v0.34.8), also directly available in some package managers.

There are 2 types of accounts: basic and validator. The accounts have string addresses, basic prefixed with `'b'` and validator with `'v'`. Accounts can have some balance of unspecified currency ¤ (type `u64`).


```shell
# Build
make

# Build the validity predicate and transaction wasm from templates, at:
# - ../vp_template/vp.wasm
# - ../tx_template/tx.wasm
make build-wasm-scripts

# Build and link the executables
make install

# Run Anoma daemon (this will also initialize and run Tendermint node)
make run

# Reset the state (resets Tendermint too)
cargo run --bin anomad -- reset

# Submit a transaction with a wasm code 
cargo run --bin anomac -- tx -c ../tx_template/tx.wasm

# Watch and on change run a node (the state will be persisted)
cargo watch -x "run --bin anomad -- run"

# Watch and on change reset & run a node
cargo watch -x "run --bin anomad -- reset" -x "run --bin anomad -- run"
```

## Logging

To change the log level, set `ANOMA_LOG` environment variable to one of:
- `error`
- `warn`
- `info`
- `debug`
- `trace`
