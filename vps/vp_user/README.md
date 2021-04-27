# A basic user validity predicate wasm

This VP currently provides a signature verification against a public key for sending tokens (receiving tokens is permissive).

## Quick start

```shell
# To be able to build this, make sure to have
make deps

# Build - this will create `vp.wasm` file
make build-release
```

The crate is configured to build into wasm in [cargo config](.cargo/config).