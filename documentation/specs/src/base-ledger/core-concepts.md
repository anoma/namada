# Consensus

Namada uses [Tendermint Go](https://github.com/tendermint/tendermint) through the [tendermint-rs](https://github.com/heliaxdev/tendermint-rs) bindings in order to provide peer-to-peer transaction gossip, BFT consensus, and state machine replication for Namada's custom state machine.

## Default account

The default account validity predicate authorises transactions on the basis of a cryptographic signature.

## Fungible token

The fungible token validity predicate authorises token balance changes on the basis of conservation-of-supply and approval-by-sender.

## k-of-n multisignature

The k-of-n multisignature validity predicate authorises transactions on the basis of k out of n parties approving them.