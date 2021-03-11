# WASM VM

A wasm virtual machine will be used for [validity predicates](./vp.md) and [transactions code](./tx-execution.md). 

The VM should provide:
- an interface for compiling from higher-level languages to wasm (initially only Rust)
- a wasm compiler, unless we use [an interpreted runtime](/explore/libraries/wasm.md)
- provide and inject [environments for higher-level languages for VPs and transactions](#wasm-environment)
- pre-process wasm modules
  - check & sanitize modules
  - inject gas metering
  - inject stack height metering
- a runner for VPs and transactions code
- encode/decode wasm for transfer & storage
- manage runtime memory
- wasm development helpers
- helpers to estimate gas usage
- VM and environment versioning

Needs more info:
- TODO: review [wasmer gas metering](https://github.com/wasmerio/wasmer/blob/1ee7b4a07ff1acaec93078e618d64c810e7691f0/examples/metering.rs), are there any loop-holes that could potentially escape metering?
- TODO: can VPs be pre-compiled/cached?

## Resources

- [WebAssembly Specifications](https://webassembly.github.io/spec/)
- [wasmer examples](https://docs.wasmer.io/integrations/examples)
- [The WebAssembly Binary Toolkit](https://github.com/webassembly/wabt/)
  - bunch of useful wasm tools (e.g. `wasm2wat` to convert from wasm binary to human-readable wat format) 
- [Rust wasm WG](https://github.com/rustwasm/team)
- [A practical guide to WebAssembly memory](https://radu-matei.com/blog/practical-guide-to-wasm-memory/) modulo JS specific details

## Wasm environment

The wasm environment will most likely be libraries that provide APIs for the wasm modules.

### Common environment

The common environment of VPs and transactions APIs:

- math & crypto
- logging
- panics/aborts
- gas metering
- storage read-only API
- context API (chain metadata such as block height)

The accounts sub-space storage is described under [accounts' dynamic storage sub-space](./accounts.md#dynamic-storage-sub-space).

### VPs environment

Because VPs are stateless, everything that's exposed in the VPs environment should be read-only:

- storage API to account's sub-space
- transaction API

### Transactions environment

- storage write access for all public state

Some exceptions as to what can be written are given under [transaction code](./tx-execution.md#tx-code).

