# The gossip network

The gossip network runs in parralel to the ledger network and is used to
propagate information like intents. The network is based on
[libp2p](https://libp2p.io/) that takes of creating a decentralize network and
encrypting any messages. On top of it, it uses the network behaviour
[GossipSub](https://github.com/libp2p/specs/tree/master/pubsub/gossipsub) that
takes care of gossiping the message to all participant and has a grading system
to bans node that does not follow the rules.

The gossip network is used to propagate message of two differents applications,
intents for the orderbook application, and message for distributed keys
generation application.

- [orderbook](./gossip/orderbook.md)
- [distributed key generation](./gossip/dkg.md)

## Gossip process

High level overview of the gossip processing

![gossip process](./gossip/gossip_process.svg  "gossip process")
