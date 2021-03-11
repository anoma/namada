# The gossip/orderbook

## High level Overview

The orderbook network is parallel to the ledger network, they are bridge
together by a matchmaker process.

```mermaid
flowchart LR
    subgraph ON [orderbook Network]
        O1(Node 1)
        O2(Node 2)
        O1 <-. intent .-> O2
        O1 <-- filter --> O2
    end
    U1[User]
    U1 -- intent --> O1
    MM[Matchmaker]
    O2 -. intent .-> MM
    MM -- tx --> L1
    subgraph LN [Ledger Network]
        L1(Node 1)
        L2(Node 2)
        L1 <-- tx --> L2
    end
    U2[User]
    U2 -- tx --> L2
```

## Incentive

Each orderbook must have an incentive to propagate intent and matchmaker to
craft transactions. The transaction contains public key of participant orderbook
and the matchmaker who crafted it.

Incentive function TBD.

```mermaid
flowchart TD
    U[User]
    U -- sign with pk 1 --> O1
    subgraph ON [orderbook Network]
        O1(Node 1)
        Ox[...]
        On(Node n)
        O1 -- sign with pk 2 --> Ox
        Ox -- sign with pk n --> On
    end
    MM[Matchmaker]
    On -.fetch intent .-> MM
    MM -- craft tx --> LN
    LN((Ledger Network))
```
