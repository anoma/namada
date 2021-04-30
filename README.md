# Anoma ledger prototype

## Quick start

The ledger currently requires that [Tendermint version 0.34.x](https://github.com/tendermint/tendermint) is installed and available on path. [The pre-built binaries and the source for 0.34.8 are here](https://github.com/tendermint/tendermint/releases/tag/v0.34.8), also directly available in some package managers.

The transaction code can currently be built from [tx_template](txs/tx_template) and validity predicates from [vp_template](vps/vp_template), which is Rust code compiled to wasm.

The transaction template calls functions from the host environment. The validity predicate template can validate a transaction and the key changes that is has performed.

The validity predicate is currently hard-coded in the shell and used for every account. To experiment with a different validity predicate, build it from the template and restart the shell.

The gossip node needs to toggle the intent flag `--intent` to activate the intent broadcaster, multiple nodes can be connected with the `--peers` option.

The matchmaker template receives intents with the borsh encoding define in `data_template` and crafts data to be sent with `tx_intent_template` to the ledger. It matches only two intents that are the exact opposite.

```shell
# Install development dependencies
make dev-deps

# Run this first if you don't have Rust wasm target installed:
make -C txs/tx_template deps

# Build the validity predicate, transaction and matchmaker wasm modules:
make build-wasm-scripts

# Build Anoma
make

# Build and link the executables
make install

# generate default config in .anoma/
cargo run --bin anomad -- --base-dir .anoma generate-config

# Run Anoma daemon (this will also initialize and run Tendermint node)
make run-ledger

# Reset the state (resets Tendermint too)
cargo run --bin anomad -- reset-ledger

# Submit a custom transaction with a wasm code and arbitrary data
cargo run --bin anoma -- tx --code txs/tx_template/tx.wasm --data tx.data

# Submit a token transfer
cargo run --bin anomac -- transfer --source alan --target ada --token xan --amount 10.1 --code txs/tx_transfer/tx.wasm

# Watch and on change run a node (the state will be persisted)
cargo watch -x "run --bin anomad -- run-ledger"

# Watch and on change reset & run a node
cargo watch -x "run --bin anomad -- reset-ledger" -x "run --bin anomad -- run"

# run gossip node daemon with intent broadcaster and rpc server (use default config)
cargo run --bin anoma -- run-gossip --rpc

# run gossip daemon with intent broadcaster, matchmaker and rpc (use default config)
cargo run --bin anomad -- run-gossip --rpc --matchmaker matchmaker_template/matchmaker.wasm --tx-template txs/tx_from_intent/tx.wasm --ledger-address "127.0.0.1:26658"

# craft two opposite intents
cargo run --bin anomac -- craft-intent --address alan --token-buy xan --amount-buy 10 --token-sell btc --amount-sell 20 --file intent_A.data
cargo run --bin anomac -- craft-intent --address ada --token-buy btc --amount-buy 20 --token-sell xan --amount-sell 10 --file intent_B.data

# Subscribe to new network
cargo run --bin anomac -- subscribe-topic --node "http://[::1]:39111" --topic "asset_v1"

# Submit the intents (need a rpc server), hardcoded address rpc node address
cargo run --bin anomac -- intent --node "http://[::1]:39111" --data intent_A.data --topic "asset_v1"
cargo run --bin anomac -- intent --node "http://[::1]:39111" --data intent_B.data --topic "asset_v1"

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
