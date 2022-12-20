## Namada

Welcome to the Namada specifications!

## What is Namada? 

Namada is a sovereign proof-of-stake blockchain, using Tendermint BFT consensus,
that enables multi-asset private transfers for any native or non-native asset
using a [multi-asset shielded pool](https://research.metastate.dev/multi-asset_shielded_pool/) derived from the [Sapling circuit](https://z.cash/upgrade/sapling/).
Namada features full IBC protocol support, a natively integrated Ethereum bridge, a modern proof-of-stake system with automatic reward compounding and cubic slashing,
a stake-weighted governance signalling mechanism, and a dual proactive/retroactive public goods funding system.
Users of shielded transfers are rewarded for their contributions to the privacy set in the form of native protocol tokens.
A multi-asset shielded transfer wallet is provided in order to facilitate safe and private user interaction with the protocol.

You can learn more about Namada [here](https://medium.com/namadanetwork/introducing-namada-shielded-transfers-with-any-assets-dce2e579384c).

### What is Anoma?

The Anoma protocol is designed to facilitate the operation of networked fractal instances, which intercommunicate but can utilise varied state machines and security models. 
A fractal instance is an instance of the Anoma consensus and execution protocols operated by a set of networked validators.
Anoma’s fractal instance architecture is an attempt to build a platform which is architecturally homogeneous but with a heterogeneous security model.
Thus, different fractal instances may specialise in different tasks and serve different communities.

### How does Namada relate to Anoma? 

The Namada instance is the first such fractal instance, focused exclusively on the use-case of private asset transfers.
Namada is also a helpful stepping stone to finalise, test, and launch a protocol version that is simpler than the full
Anoma protocol but still encapsulates a unified and useful set of features. 

### Raison d'être

Privacy should be default and inherent in the systems we use for transacting, yet safe and user-friendly multi-asset privacy doesn't yet exist in the blockchain ecosystem.
Up until now users have had the choice of either a sovereign chain that reissues assets (e.g. [Zcash](https://z.cash/))
or a privacy preserving solution built on an existing smart contract chain. Both have large trade-offs: in the former case, users don't have
assets that they actually want to transact with, and in the latter case, the restrictions
of existing platforms mean that users leak a ton of metadata
and the protocols are expensive and clunky to use.

Namada can support any fungible or non-fungible asset on an IBC-compatible blockchain
and fungible or non-fungible assets (such as ERC20 tokens) sent over a custom Ethereum bridge that
reduces transfer costs and streamlines UX as much as possible. Once assets are on Namada,
shielded transfers are cheap and all assets contribute to the same anonymity set.

Users on Namada can earn rewards, retain privacy of assets, and contribute to shared privacy. 

### Layout of this specification

The Namada specification documents are organised into four sub-sections:

- [Base ledger](./base-ledger.md)
- [Multi-asset shielded pool](./masp.md)
- [Interoperability](./interoperability.md)
- [Economics](./economics.md)

This book is written using [mdBook](https://rust-lang.github.io/mdBook/), the source can be found in the [Namada repository](https://github.com/anoma/namada/tree/main/documentation/specs).

[Contributions](https://github.com/anoma/namada/blob/main/CONTRIBUTING.md) to the contents and the structure of this book should be made via pull requests.