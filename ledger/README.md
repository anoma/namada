# Anoma ledger prototype

## Quick start

The ledger currently requires that [Tendermint version 0.34.x](https://github.com/tendermint/tendermint) is installed and available on path. [The pre-built binaries and the source for 0.34.8 are here](https://github.com/tendermint/tendermint/releases/tag/v0.34.8), also directly available in some package managers.

There are 2 types of accounts: basic and validator. The accounts have string addresses, basic prefixed with `'b'` and validator with `'v'`. Accounts can have some balance of unspecified currency ¤ (type `u64`).


```shell
# Build
make

# Build and link the executables
make install

# Run Anoma daemon (this will also initialize and run Tendermint node)
make run-anoma

# Reset the state (resets Tendermint too)
cargo run --bin anomad -- reset

# Submit a transfer from "va" to "ba" of 10¤ to the Tendermint node
cargo run --bin anomac -- transfer -s va -d ba -a 10

# Watch and on change run a node (the state will be persisted)
cargo watch -x "run --bin anomad -- run-anoma"

# Watch and on change reset & run a node
cargo watch -x "run --bin anomad -- reset-anoma" -x "run --bin anomad -- run"

# run orderbook daemon
make run-orderbook

# run orderbook daemon with rpc server
cargo run --bin anomad -- --rpc run-orderbook

# Submit an intent (need a rpc server)
cargo run --bin anomac -- gossip -data "data"
```

## Logging

To change the log level, set `ANOMA_LOG` environment variable to one of:
- `error`
- `warn`
- `info`
- `debug`
- `trace`
