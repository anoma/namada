# Validity predicate wasm template

This is just a template of a wasm module for VP. The functionality initially inlined in here will be modularized into Anoma wasm VM and a VP environment.

## Quick start

```shell
# To be able to build this, make sure to have
make deps

# Build - this will create `vp.wasm` file
make build-release
```

The crate is configured to build into wasm in [cargo config](.cargo/config).