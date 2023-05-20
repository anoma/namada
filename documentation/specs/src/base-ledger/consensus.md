# Consensus

Namada uses [CometBFT](https://github.com/cometbft/cometbft/) (nee Tendermint Go) through the [cometbft-rs](https://github.com/heliaxdev/tendermint-rs) (nee tendermint-rs) bindings in order to provide peer-to-peer transaction gossip, BFT consensus, and state machine replication for Namada's custom state machine. CometBFT implements the Tendermint consensus algorithm, which you can read more about [here](https://arxiv.org/abs/1807.04938).
