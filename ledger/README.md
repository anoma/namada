# Anoma ledger prototype

## Quick start

The ledger currently requires that [Tendermint version 0.34.x](https://github.com/tendermint/tendermint) is installed and available on path. [The pre-built binaries and the source for 0.34.8 are here](https://github.com/tendermint/tendermint/releases/tag/v0.34.8), also directly available in some package managers.

There are 2 types of accounts: basic and validator. The accounts have string addresses, basic prefixed with `'b'` and validator with `'v'`. Accounts can have some balance of unspecified currency ¤ (type `u64`).

The transaction code can currently be built from [tx_template](../tx_template) and validity predicates from [vp_template](../vp_template), which is Rust code compiled to wasm.

The transaction template calls `transfer` function from the host environment (Anoma shell) with some hard-coded values for the transfer source, destination and amount (this is temporary until we have more complete storage API for transactions).

The validity predicate template receives the `transfer` data and checks that the transfer's amount > 0.

The validity predicate is currently hard-coded in the shell and used for every account. To experiment with a different validity predicate, build it from the template and restart the shell.

Multiple gossip nodes can be run, each should toggle orderbook to relay.

The matchmaker template receive intent with the borsh encoding define in `data_template` and craft data to be send with `tx_intent_template` to the ledger.


The gossip node needs to toggle the orderbook flag `--orderbook` to relay intents, multiple nodes can be connected with the `--peers` option.

The matchmaker template receive intent with the borsh encoding define in `data_template` and craft data to be send with `tx_intent_template` to the ledger. It matches only two intents that are the exact opposite.

```shell
# Install development dependencies
make dev-deps

# Run this first if you don't have Rust wasm target installed:
make -C ../tx_template deps

# Build the validity predicate and transaction wasm from templates, at:
# - ../vp_template/vp.wasm
# - ../tx_template/tx.wasm
make build-wasm-scripts

# Build Anoma
make

# Build and link the executables
make install

# Run Anoma daemon (this will also initialize and run Tendermint node)
make run-anoma

# Reset the state (resets Tendermint too)
cargo run --bin anomad -- reset-anoma

# Submit a transaction with a wasm code
cargo run --bin anomac -- tx -c ../tx_template/tx.wasm

# Watch and on change run a node (the state will be persisted)
cargo watch -x "run --bin anomad -- run-anoma"

# Watch and on change reset & run a node
cargo watch -x "run --bin anomad -- reset-anoma" -x "run --bin anomad -- run"

# run orderbook daemon
make run-gossip

# run orderbook daemon with rpc server and matchmaker
cargo run --bin anomad -- --rpc run-gossip --orderbook --matchmaker ../matchmaker_template/matchmaker.wasm --tx-template ../tx_intent_template/tx.wasm --ledger-address  "tcp://127.0.0.1:26658"

# craft an intent to file `intent_data_file`
cargo run --bin anomac -- craft-intent --addr account_name --token-buy xtz --amount-buy 10 --token-sell eth --amount-sell 20 --file intent_data_file

# Submit an intent (need a rpc server)
cargo run --bin anomac -- intent intent_data_file

# Format the code
make fmt
```

## Logging

To change the log level, set `ANOMA_LOG` environment variable to one of:
- `error`
- `warn`
- `info`
- `debug`
- `trace`

To reduce amount of logging from Tendermint ABCI, which has a lot of `debug` logging, use e.g. `ANOMA_LOG=debug,tendermint_abci=warn`.
