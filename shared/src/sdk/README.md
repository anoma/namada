# The Namada SDK

The Namada SDK is a set of tools and libraries that allow you to use the Namada API in your own applications.

## Table of Contents

- [Installation](#installation)
- [SDK modules](#sdk-modules)
  - [Wallet](#wallet)
  - [Queries](#queries)
  - [Signing](#signing)
  - [Transactions](#transactions)
  - [MASP](#masp)
  - [Rpc](#rpc)
  - [Errors](#errors)

## Installation

The Namada SDK can be added into any Rust project using cargo by adding the following to your `Cargo.toml` file `[dependencies]` section:

```toml
[dependencies]
borsh = "0.9.0"
masp_primitives = { git = "https://github.com/anoma/masp" }
masp_proofs = { git = "https://github.com/anoma/masp", default-features = false, features = ["local-prover"] }
namada = { git = "https://github.com/anoma/namada", default-features = false, features = ["abciplus", "namada-sdk"] }

```

Once the dependencies are added, you can use the SDK in your rust project by adding the following to your `main.rs` file:

```rust
use namada_sdk::wallet::Wallet;

...
```

Before executing any transactions, it is important to build using `cargo build`

## SDK modules

### Wallet

The wallet module allows the developer to create, store and manage Namada wallets. All key management is handled by the wallet module, including eth_bridge keys, validator consensus keys, transparent keys, and shielded keys.

### Queries

The queries module allows the developer to query the Namada ledger state. This includes querying the balance of a given address, the status of a governance proposal, and the status of the latest block.

### Signing

The signing module allows the developer to sign Namada transactions before they are submitted. It also handles multi-signature signing.

### Transactions

The transactions module allows the developer to create and sign Namada transactions. For example, the developer can create a transaction to transfer funds from one address to another, or to create a new governance proposal.

### MASP

The MASP module gives the developer access to Multi-asset Shielded Pool functionality. This includes shielding and unshielding assets, and transferring funds between shielded addresses.

### Rpc

The rpc module allows the developer to query the Namada RPC server. The functionality is similar to that of the queries module, but the rpc module allows the developer to query the RPC server directly, rather than querying the ledger state.

### Errors

The errors module contains all the errors that can be used within the SDK context. This is especially useful for handling errors returned by the SDK.



