# Base ledger prototype

tracking issue <https://github.com/heliaxdev/rd-pm/issues/5>

## Goals

- get some hands-on experience with Rust and Tendermint
- initial usable node + client (+ validator?) setup
- provide a base layer for other prototypes that need to build on top of a ledger

## Components

The main components are built in a single Cargo project with [shared library code](#shared) and multiple binaries:
- `anoma` - main executable with commands for both the node and the client (`anoma node` and `anoma client`)
- `anomad` - the [node](#node)
- `anomac` - the [client](#client)

### Node

The node is built into `anomad`.

#### Shell

The shell is what currently pulls together all the other components in the node.

When it's ran:
- establish a channel (e.g.`mpsc::channel` - Multi-producer, single-consumer FIFO queue) for communication from tendermint to the shell
- launch tendermint node in another thread with the channel sender
  - send tendermint ABCI requests via the channel together with a new channel sender to receive a response
- run shell loop with the channel receiver, which handles ABIC requests:
  - [transaction execution](/explore/design/ledger/tx-execution.md) which includes [wasm VM calls](/explore/design/ledger/wasm-vm.md)

##### Tendermint

This module handles initializing and running `tendermint` and forwards messages for the ABCI requests via its channel sender.

#### Storage

Key-value storage. More details being specified: WIP in <https://github.com/heliaxdev/rd-pm/pull/37/files#diff-3d006fbf4395f551596925fb96a3ced8a2b24ef5bc918b9872140e9889414606R63>

#### CLI

- `anoma run` to start the node (will initialize (if needed) and launch tendermint under the hood)
- `anoma reset` to delete all the node's state from DB and tendermint's state

### Client

Allows to submit a transaction with an attached wasm code to the node with:

`anoma tx --code tx.wasm`

It presents back the received response on stdout. Currently, it waits for both the mempool validation and application in a block.

### Shared

#### Config

Configuration settings:
- home directory (db storage and tendermint config and data)

#### Genesis

The genesis parameters, such as the initial validator set, are used to initialize a chain's genesis block.

#### RPC types

The types for data that can be submitted to the node via the client's RPC commands.
