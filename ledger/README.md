# Anoma ledger prototype

The ledger currently requires that [Tendermint version 0.33.x](https://github.com/tendermint/tendermint) is installed and available on path. The newer versions 0.34.x are not yet supported. [The pre-built binaries and the source for 0.33.9 are here](https://github.com/tendermint/tendermint/releases/tag/v0.33.9).

Handy commands:

```shell
# Build
make

# Build and link the executables
make install

# Run Anoma daemon (this will also initialize and run Tendermint node)
make run

# Reset the state (resets Tendermint too), ...
cargo run --bin anomad -- reset
# ...or shorter when executables are installed:
anoma reset

# Submit a transaction to the Tendermint node, ...
cargo run --bin anomac -- transfer -c 1
# ...or shorter when executables are installed:
anoma transfer -c 1
```
