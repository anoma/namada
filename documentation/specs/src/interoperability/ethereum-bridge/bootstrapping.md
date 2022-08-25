# Bootstrapping the bridge

The Ethereum bridge is not enabled at the launch of a Namada chain. Instead, there is a governance parameter, `eth_bridge_proxy_address`, which is initialized to the zero Ethereum address (`"0x0000000000000000000000000000000000000000"`). An overview of the steps to enable the Ethereum bridge for a given Namada chain are:

- A governance proposal should be held to agree on a block height `l` at which to launch the Ethereum bridge by means of a hard fork.
- If the proposal passes, the Namada chain must halt after finalizing block `l-1`.
- The [Ethereum bridge smart contracts](./ethereum_smart_contracts.md) are deployed to the relevant EVM chain, with the active validator set at block height `l` as the initial validator set that controls the bridge.
- Details are published so that the deployed contracts can be verified by anyone who wishes to do so.
- If active validators for block height `l` regard the deployment as valid, the chain should be restarted with a new genesis file that specifies `eth_bridge_proxy_address` as the Ethereum address of the proxy contract.

At this point, the bridge is launched and it may start being used. Validators' ledger nodes will immediately and automatically coordinate in order to craft the first validator set update protocol transaction.

## Governance proposal

The governance proposal can be freeform and simply indicate what the value of `l` should be. Validators should then configure their nodes to halt at this height.

## Value for launch height `l`

The active validator set at the launch height chosen for starting the Ethereum bridge will have the extra responsibility of restarting the chain if they consider the deployed smart contracts as valid. For this reason, the validator set at this height should ideally be known in advance of the governance proposal resolving, and a channel set up for offchain communication and co-ordination of the chain restart.

## Deployer

Once the smart contracts are fully deployed, only the active validator set for block height `l` should have control of the contracts so in theory anyone could do the Ethereum bridge smart contract deployment.

## Backing out of Ethereum bridge launch

If for some reason the validity of the smart contract deployment cannot be agreed upon by the validators who will responsible for restarting Namada, it must remain possible to restart the chain with the Ethereum bridge still not enabled i.e. with `eth_bridge_proxy_address = "0x0000000000000000000000000000000000000000"`.
