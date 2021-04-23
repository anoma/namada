# The gossip network

The gossip network runs in parallel to the ledger network and is used to
propagate off-chain information. The network is based on
[libp2p](https://libp2p.io/) that takes of creating a decentralized network and
encrypting any messages. On top of it, it uses the network behavior
[GossipSub](https://github.com/libp2p/specs/tree/master/pubsub/gossipsub), that
takes care of gossiping the message to all participant and has a grading system
to ban node that does not follow the
rules.

The gossip network is used to propagate messages of two different applications,
intents for the intent broadcaster, and message for distributed keys generation
application.

- [intent broadcaster](./intent_broadcaster.md)
- [distributed key generation](./dkg_broadcaster.md)

## High level overview of network interaction

![gossip process](./intent_broadcaster/gossip_process.svg  "gossip process")

[exilidraw link](https://excalidraw.com/#room=5d4a2a84ef52cf5f5f96,r4ghl40frJ9putMy-0vyOQ)
