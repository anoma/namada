# Transaction script wasm for updating an account's validity predicate

This is a wasm module for updating an account's validity predicate. This template wraps the validity predicate inside `key::ed25519::SignedTxData` as its input as declared in `shared` crate. 

## Quick start

```shell
# To be able to build this, make sure to have
make deps

# Build - this will create `tx.wasm` file
make build-release
```

The crate is configured to build into wasm in [cargo config](.cargo/config).
