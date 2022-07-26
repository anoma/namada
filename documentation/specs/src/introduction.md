## Namada

Welcome to the Namada specifications!

Namada is a sovereign proof-of-stake blockchain, using Tendermint BFT consensus,
that enables multi-asset private transfers for any native or non-native asset
using a multi-asset shielded pool derived from the Sapling circuit. Namada features
full IBC protocol support, a natively integrated Ethereum bridge, a modern proof-of-stake
system with automatic reward compounding and cubic slashing, a stake-weighted governance
signalling mechanism, and a proactive/retroactive public goods funding system.
Users of shielded transfers are rewarded for their contributions
to the privacy set in the form of native protocol tokens. A multi-asset shielded transfer wallet
is provided in order to facilitate safe and private user interaction with the protocol.

### How does Namada relate to Anoma?

Namada is the first fractal instance launched as part of the Anoma ecosystem.

The Anoma protocol is designed to facilitate the operation of networked fractal instances,
which intercommunicate but can utilise varied state machines and security models. Different
fractal instances may specialise in different tasks and serve different communities. The Namada
instance will be the first such fractal instance, and it will be focused exclusively on the use-case of private asset transfers.

### Raison d'être

Safe and user-friendly multi-asset privacy doesn't yet exist in the blockchain ecosystem.
Up until now users have had the choice of either a sovereign chain that reissues assets (e.g. Zcash)
or a privacy preserving solution built on an existing smart contract chain (e.g. Tornado Cash on
Ethereum). Both have large trade-offs: in the former case, users don't have
assets that they actually want to transact with, and in the latter case, the restrictions
of existing platforms mean that users leak a ton of metadata
and the protocols are expensive and clunky to use.

Namada can support any fungible or non-fungible asset on an IBC-compatible blockchain
and fungible or non-fungible assets (such as ERC20 tokens) sent over a custom Ethereum bridge that
reduces transfer costs and streamlines UX as much as possible. Once assets are on Namada,
shielded transfers are cheap and all assets contribute to the same anonymity set.

Namada is also a helpful stepping stone to finalise, test,
and launch a protocol version that is simpler than the full
Anoma protocol but still encapsulates a unified and useful
set of features. There are reasons to expect that it may
make sense for a fractal instance focused exclusively on
shielded transfers to exist in the long-term, as it can
provide throughput and user-friendliness guarantees which
are more difficult to provide with a more general platform.
Namada is designed to be such an instance.

### Layout of this specification

The Namada specification documents are organised into four sub-sections:

- [Base ledger](./base-ledger.md)
- [Multi-asset shielded pool](./masp.md)
- [Interoperability](./interoperability.md)
- [Economics](./economics.md)
