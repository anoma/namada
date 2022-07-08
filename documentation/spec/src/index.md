# Namada

Namada is the first release protocol version and the first fractal instance of the Anoma protocol.
Namada is a sovereign proof-of-stake blockchain, using Tendermint BFT consensus,
that enables multi-asset private transfers for any native or non-native asset
using a multi-asset shielded pool derived from the Sapling circuit. Namada features
full IBC protocol support, a natively integrated Ethereum bridge, a modern proof-of-stake
system with automatic reward compounding and cubic slashing, and a stake-weighted governance
signalling mechanism. Users of shielded transfers are rewarded for their contributions
to the privacy set in the form of native protocol tokens. A multi-asset shielded transfer wallet is provided in order to facilitate
safe and private user interaction with the protocol.

## How does Namada relate to Anoma?

Namada is _two things_:
- The first major release _version_ of the Anoma protocol.
- The first _fractal instance_ launched as part of the Anoma network.

The Anoma protocol is designed to facilitate the operation of networked fractal instances,
which intercommunicate but can utilise varied state machines and security models. Different
fractal instances may specialise in different tasks and serve different communities. The Namada
instance will be the first such fractal instance, and it will be focused exclusively on the use-case of private asset transfers.

## Raison d'être

Safe and user-friendly multi-asset privacy doesn't yet exist in the blockchain ecosystem.
Up until now you had the choice to build a sovereign chain that reissues assets (e.g. Zcash) or to
build a privacy preserving solution on existing chains (e.g. Tornado Cash on
Ethereum). Both have large trade-offs: in the former case users don't have
assets that they actually want to use and in the latter case the restrictions
of existing platforms mean that users leak a ton of metadata
and the protocols are expensive and clunky to use.

Namada can support any asset on an IBC-compatible blockchain
and assets (such as ERC20 tokens) sent over a custom Ethereum bridge that
reduces transfer costs and streamlines UX as much as possible.
Once assets are on Namada, shielded transfers are cheap
and all assets contribute to the same anonymity set.

Namada is also a helpful stepping stone to finalise, test,
and launch a protocol version that is simpler than the full
Anoma protocol but still encapsulates a unified and useful
set of features. There are reasons to expect that it may
make sense for a fractal instance focused exclusively on
shielded transfers to exist in the long-term, as it can
provide throughput and user-friendliness guarantees which
are more difficult to provide with a more general platform.
Namada is designed so that it could evolve into such an instance.

## Layout of this specification

The Namada specification documents are organised into five sub-sections:
- [Base ledger](./base-ledger.md)
- [Multi-asset shielded pool](./masp.md)
- [Interoperability](./interoperability.md)
- [Economics](./economics.md)
- [User interfaces](./user-interfaces.md)