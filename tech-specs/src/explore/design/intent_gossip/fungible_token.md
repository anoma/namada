# Fungible token encoding and template

The Heliax team implemented an intent encoding, a filter program template and a
matchmaker program template that can be used to exchange fungible tokens between
any number of participants.

## Intent encoding
The intent encoding allows to express a desire to participate in an asset
exchange. The encoding is define as follow :

```rust
struct FungibleToken {
    address: Address
    token_sell: Address
    max_sell: Amount
    rate_min: f64
    token_buy: Address
    min_buy: Amount
    expire: Time::Instant
}
```

## Matchmaker program

The filter program attempts to decode the intent and if successful, it checks
that it's not yet expired and that the account address has enough funds for the
intended selled token.

The main program can match intents for exchanging assets. It does that by
creating a graph from all intents. When a cycle is found then it removes all
intents from that cycle of the mempool and crafts a transaction based on all the
removed intents.

![matchmaker](matchmaker_graph.svg)
[excalidraw link](https://excalidraw.com/#room=1db86ba6d5f0ccb7447c,2vvRd4X2Y3HDWHihJmy9zw)
