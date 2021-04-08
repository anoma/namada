# Transaction script wasm template

This is just a template of a wasm module for transaction script. This template
uses `TxData` as its input as declared in `data_template` crate. It's used by the matchmaker that crafts transactions from matched intents. It's also possible to craft the data using the client, which would create a file with the serialized data, that can be submitted directly to the ledger.

## Quick start

```shell
# To be able to build this, make sure to have
make deps

# Build - this will create `tx.wasm` file
make build-release
```

The crate is configured to build into wasm in [cargo config](.cargo/config).
