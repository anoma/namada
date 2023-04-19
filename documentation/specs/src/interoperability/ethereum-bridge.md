# Ethereum bridge

Namada's bridge to Ethereum exists to allow transfers of both fungible and
non-fungible tokens in either direction (Namada $\Leftrightarrow$ Ethereum).

Fungible token transfers roughly implement the [ICS20] spec. Wrapped [ERC20]
tokens are minted on Namada which naturally can be redeemed on Ethereum at a
later time. Furthermore, it allows the minting of wrapped NAM (wNAM) ERC20
tokens on Ethereum. All wrapped fungible assets are burned, when transferred
back to their native platform. When transferred out of their native platform,
fungible assets are held in escrow.

[ICS20]: <https://github.com/cosmos/ibc/blob/ed849c7bacf16204e9509f0f0df325391f3ce25c/spec/app/ics-020-fungible-token-transfer/README.md>
[ERC20]: <https://eips.ethereum.org/EIPS/eip-20>

The Namada Ethereum bridge system consists of:

* A set of Ethereum smart contracts.
* An Ethereum full node run by each Namada validator, to watch Ethereum
  events emitted by the bridge's smart contracts.
* A set of validity predicates (VPs) on Namada.
    + A Bridge pool VP, to validate transfers to Ethereum and escrowed NAM.
    + An Ethereum bridge VP, to protect writes to Namada storage
      key sub-spaces containing Ethereum event tallies.
* Two relayer utilities, to call the Ethereum smart contracts.
    + One for performing validator set updates on the Ethereum
      smart contracts.
    + Another to aid in submitting batches of transactions
      to Ethereum.

This basic bridge architecture should provide for almost-Namada consensus
security for the bridge and free Ethereum state reads on Namada, plus
bidirectional message passing with reasonably low gas costs on the
Ethereum side.

## Topics
 - [Bootstrapping](./ethereum-bridge/bootstrapping.md)
 - [Security](./ethereum-bridge/security.md)
 - [Ethereum Events Attestation](./ethereum-bridge/ethereum_events_attestation.md)
 - [Transfers from Ethereum to Namada](./ethereum-bridge/transfers_to_namada.md)
 - [Transfers from Namada to Ethereum](./ethereum-bridge/transfers_to_ethereum.md)
 - [Proofs and validator set updates](./ethereum-bridge/proofs.md)
 - [Smart Contracts](./ethereum-bridge/ethereum_smart_contracts.md)

## Resources which may be helpful:
- [Gravity Bridge Solidity contracts](https://github.com/Gravity-Bridge/Gravity-Bridge/tree/main/solidity)
- [ICS20]
- [Rainbow Bridge contracts](https://github.com/aurora-is-near/rainbow-bridge/tree/master/contracts)
- [IBC in Solidity](https://github.com/hyperledger-labs/yui-ibc-solidity)
