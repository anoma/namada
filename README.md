# Anoma ledger prototype

## Quick start

The ledger currently requires that [Tendermint version 0.34.x](https://github.com/tendermint/tendermint) is installed and available on path. [The pre-built binaries and the source for 0.34.8 are here](https://github.com/tendermint/tendermint/releases/tag/v0.34.8), also directly available in some package managers.

The transaction code can currently be built from [tx_template](../tx_template) and validity predicates from [vp_template](../vp_template), which is Rust code compiled to wasm.

The transaction template calls functions from the host environment. The validity predicate template can validate a transaction and the key changes that is has performed.

The validity predicate is currently hard-coded in the shell and used for every account. To experiment with a different validity predicate, build it from the template and restart the shell.

The gossip node needs to toggle the orderbook flag `--orderbook` to relay intents, multiple nodes can be connected with the `--peers` option.

The matchmaker template receives intents with the borsh encoding define in `data_template` and crafts data to be sent with `tx_intent_template` to the ledger. It matches only two intents that are the exact opposite.

```shell
# Install development dependencies
make dev-deps

# Run this first if you don't have Rust wasm target installed:
make -C tx_template deps

# Build the validity predicate, transaction and matchmaker wasm modules:
make build-wasm-scripts

# Build Anoma
make

# Build and link the executables
make install

# generate default config in .anoma/
cargo run --bin anomad -- generate-config

# Run Anoma daemon (this will also initialize and run Tendermint node)
make run-ledger

# Reset the state (resets Tendermint too)
cargo run --bin anomad -- reset-ledger

# craft a transaction data to file `tx.data`
cargo run --bin anomac -- craft-tx-data --source alan --target ada --token xan --amount 10 --file tx.data

# Submit a transaction with a wasm code
cargo run --bin anoma -- tx --path tx_template/tx.wasm --data tx.data

# Watch and on change run a node (the state will be persisted)
cargo watch -x "run --bin anomad -- run-ledger"

# Watch and on change reset & run a node
cargo watch -x "run --bin anomad -- reset-ledger" -x "run --bin anomad -- run"

# run orderbook daemon with rpc server with default config file (or add --intent)
cargo run --bin anoma -- run-gossip --rpc

# run orderbook daemon with rpc server and matchmaker with default config file (or add --intent)
cargo run --bin anomad -- run-gossip --rpc --matchmaker matchmaker_template/matchmaker.wasm --tx-template tx_template/tx.wasm --ledger-address "127.0.0.1:26658"

# craft two opposite intents
cargo run --bin anomac -- craft-intent --address alan --token-buy xan --amount-buy 10 --token-sell btc --amount-sell 20 --file intent_A.data
cargo run --bin anomac -- craft-intent --address ada --token-buy btc --amount-buy 20 --token-sell xan --amount-sell 10 --file intent_B.data

# Submit the intents (need a rpc server), hardcoded address
cargo run --bin anomac -- intent --node "http://[::1]:39111" --data intent_A.data
cargo run --bin anomac -- intent --node "http://[::1]:39111" --data intent_B.data

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
