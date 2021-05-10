# Gossip layer/Orderbook prototype

tracking issue <https://github.com/heliaxdev/anoma-prototype/issues/35>

## Goals

- learning rust
- usable node + client setup :
  - intent
  - incentive function
  - mempool and white list
- basic matchmaker

## components

The orderbook is build conjointly to the ledger and share the same binary.

### Node

The node is built into `anoman`, it runs all the necesarry part, rpc server,
libp2p, orderbook app.

#### Orderbook

The orderbook application

##### Mempool

##### Filter

#### Network behaviour
The network behaviour is the part that react on network event. It creates a
channel (e.g. `tokio::mpsc::channel`) with the orderbook to communicate all
intent it receive.

#### Rpc server
If the rpc command line option is set it creates a tonic server that receive
command from a client and send theses through a channel
(e.g. `tokio::mpsc::channel`) to the the orderbook.

### Client
Allow to submit a intent :
`anoma gossip --data "data"`
