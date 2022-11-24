# Namada

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](./LICENSE)

## Overview

[Namada](http://namada.net) is a Proof-of-Stake L1 for interchain asset-agnostic privacy. Namada uses Tendermint BFT
consensus and enables multi-asset shielded transfers for any native
or non-native asset. Namada features full IBC protocol support,
a natively integrated Ethereum bridge, a modern proof-of-stake
system with automatic reward compounding and cubic slashing, and a
stake-weighted governance signalling mechanism. Users of shielded
transfers are rewarded for their contributions to the privacy set in
the form of native protocol tokens. A multi-asset shielded transfer
wallet is provided in order to facilitate safe and private user
interaction with the protocol.

* Blogpost: [Introducing Namada: Shielded transfers with any assets](https://medium.com/namadanetwork/introducing-namada-shielded-transfers-with-any-assets-dce2e579384c)

## 📓 Docs

* user docs: built from [docs mdBook](./documentation/docs/)
* dev docs: built from [dev mdBook](./documentation/dev/)
* specifications: built from [specs mdBook](./documentation/specs/)

## Warning

> Here lay dragons: this codebase is still experimental, try at your own risk!

## 💾 Installing

There is a single command to build and install Namada executables from source (the node, the client and the wallet). This command will also verify that a compatible version of [Tendermint](#dependencies) is available and if not, attempt to install it. Note that currently at least 16GB RAM is needed to build from source.

```shell
make install
```

After installation, the main `namada` executable will be available on path.

To find how to use it, check out the [User Guide section of the docs](https://docs.namada.net/user-guide/index.html).

For more detailed instructions and more install options, see the [Install
section](https://docs.namada.net/user-guide/install.html) of the User
Guide.

## ⚙️ Development

```shell
# Build the provided validity predicate and transaction wasm modules
make build-wasm-scripts-docker

# Development (debug) build Namada, which includes a validator and some default 
# accounts, whose keys and addresses are available in the wallet
NAMADA_DEV=true make
```

### Before submitting a PR, pls make sure to run the following

```shell
# Format the code
make fmt

# Lint the code
make clippy
```

## 🧾 Logging

To change the log level, set `NAMADA_LOG` environment variable to one of:

* `error`
* `warn`
* `info`
* `debug`
* `trace`

The default is set to `info` for all the modules, expect for Tendermint ABCI, which has a lot of `debug` logging.

For more fine-grained logging levels settings, please refer to the [tracing subscriber docs](https://docs.rs/tracing-subscriber/0.2.18/tracing_subscriber/struct.EnvFilter.html#directives) for more information.

To switch on logging in tests that use `#[test]` macro from `test_log::test`, use `RUST_LOG` with e.g. `RUST_LOG=info cargo test -- --nocapture`.

## How to contribute

Please see the [contributing page](./CONTRIBUTING.md).

### Dependencies

The ledger currently requires that [Tendermint version 0.34.x](https://github.com/tendermint/tendermint) is installed and available on path. [The pre-built binaries and the source for 0.34.8 are here](https://github.com/tendermint/tendermint/releases/tag/v0.34.8), also directly available in some package managers.

This can be installed by `make install` command (which runs [scripts/install/get_tendermint.sh](scripts/install/get_tendermint.sh) script).
