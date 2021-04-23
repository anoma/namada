# Orderbook

## High level Overview

The orderbook use the gossip network to propagates intents. An intent is
composed of arbitrary data that contains the desire of a user, from asset
exchange to a green tax pourcent for sellling shoes. Theses intents are picked
up by a matchmaker that composed them into a valid transaction to send to the
ledger network.

### example of process:
![orderbook and ledger network interaction ](./orderbook_network.svg  "orderbook network")

# Complete life cycle

![intent life cycle](./intent_life_cycle.svg "intent life cycle")
