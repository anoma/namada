# Ethereum bridge

The Namada - Ethereum bridge exists to mint wrapped ERC20 tokens on Namada 
which naturally can be redeemed on Ethereum at a later time. Furthermore, it 
allows the minting of wrapped Namada-native NAM (wNAM) on Ethereum backed 
by escrowed NAM on Namada.

The Namada Ethereum bridge system consists of:

* An Ethereum full node run by each Namada validator, for including relevant 
  Ethereum events into Namada.
* A set of validity predicates on Namada which roughly implements 
  [ICS20](https://docs.cosmos.network/v0.42/modules/ibc/) fungible token 
  transfers.
* A set of Ethereum smart contracts.
* A relayer for submitting transactions to Ethereum.

This basic bridge architecture should provide for almost-Namada consensus
security for the bridge and free Ethereum state reads on Namada, plus
bidirectional message passing with reasonably low gas costs on the
Ethereum side.

## Resources which may be helpful

- [Gravity Bridge Solidity contracts](https://github.com/Gravity-Bridge/Gravity-Bridge/tree/main/solidity)
- [ICS20](https://github.com/cosmos/ibc/tree/master/spec/app/ics-020-fungible-token-transfer)
- [Rainbow Bridge contracts](https://github.com/aurora-is-near/rainbow-bridge/tree/master/contracts)
- [IBC in Solidity](https://github.com/hyperledger-labs/yui-ibc-solidity)

Operational notes:
1. We will bundle the Ethereum full node with the `namada` daemon executable.
