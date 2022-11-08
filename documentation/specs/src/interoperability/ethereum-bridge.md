# Ethereum bridge

The Namada - Ethereum bridge exists to mint ERC20 tokens on Namada 
which naturally can be redeemed on Ethereum at a later time. Furthermore, it 
allows the minting of wrapped NAM (wNAM) tokens on Ethereum.

The Namada Ethereum bridge system consists of:

* An Ethereum full node run by each Namada validator, for including relevant 
  Ethereum events into Namada.
* A set of validity predicates on Namada which roughly implements 
  [ICS20](https://docs.cosmos.network/v0.42/modules/ibc/) fungible token 
  transfers.
* A set of Ethereum smart contracts.
* An automated process to send validator set updates to the Ethereum smart 
  contracts.
* A relayer binary to aid in submitting transactions to Ethereum

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

## Resources which may be helpful

- [Gravity Bridge Solidity contracts](https://github.com/Gravity-Bridge/Gravity-Bridge/tree/main/solidity)
- [ICS20](https://github.com/cosmos/ibc/tree/master/spec/app/ics-020-fungible-token-transfer)
- [Rainbow Bridge contracts](https://github.com/aurora-is-near/rainbow-bridge/tree/master/contracts)
- [IBC in Solidity](https://github.com/hyperledger-labs/yui-ibc-solidity)
