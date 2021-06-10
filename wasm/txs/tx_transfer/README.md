# Transaction script wasm for a token transfer

This is a wasm module for token transfer transaction. This template uses `token::Transfer` wrapped inside `key::ed25519::SignedTxData` as its input as declared in `shared` crate. 

## Quick start

```shell
# To be able to build this, make sure to have
make deps

# Build - this will create `tx.wasm` file
make build-release
```

The crate is configured to build into wasm in [cargo config](.cargo/config).
