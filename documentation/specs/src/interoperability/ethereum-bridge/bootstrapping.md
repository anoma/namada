# Bootstrapping the bridge

## Overview
The Ethereum bridge is not enabled at the launch of a Namada chain. Instead, there is a governance parameter, `eth_bridge_proxy_address`, which is initialized to the zero Ethereum address (`"0x0000000000000000000000000000000000000000"`). An overview of the steps to enable the Ethereum bridge for a given Namada chain are:

- A governance proposal should be held to agree on a block height `l` at which to launch the Ethereum bridge by means of a hard fork.
- If the proposal passes, the Namada chain must halt after finalizing block `l-1`. This requires
- The [Ethereum bridge smart contracts](./ethereum_smart_contracts.md) are deployed to the relevant EVM chain, with the active validator set at block height `l` as the initial validator set that controls the bridge.
- Details are published so that the deployed contracts can be verified by anyone who wishes to do so.
- If active validators for block height `l` regard the deployment as valid, the chain should be restarted with a new genesis file that specifies `eth_bridge_proxy_address` as the Ethereum address of the proxy contract.

At this point, the bridge is launched and it may start being used. Validators' ledger nodes will immediately and automatically coordinate in order to craft the first validator set update protocol transaction.

## Facets

### Governance proposal

The governance proposal can be freeform and simply indicate what the value of `l` should be. Validators should then configure their nodes to halt at this height.

### Value for launch height `l`

The active validator set at the launch height chosen for starting the Ethereum bridge will have the extra responsibility of restarting the chain if they consider the deployed smart contracts as valid. For this reason, the validator set at this height should ideally be known in advance of the governance proposal resolving, and a channel set up for offchain communication and co-ordination of the chain restart.

### Deployer

Once the smart contracts are fully deployed, only the active validator set for block height `l` should have control of the contracts so in theory anyone could do the Ethereum bridge smart contract deployment.

### Backing out of Ethereum bridge launch

If for some reason the validity of the smart contract deployment cannot be agreed upon by the validators who will responsible for restarting Namada, it must remain possible to restart the chain with the Ethereum bridge still not enabled i.e. with `eth_bridge_proxy_address = "0x0000000000000000000000000000000000000000"`.

## Example

In this example, all epochs are assumed to be `100` blocks long, and the active validator set does not change at any point.

- A governance proposal is made to launch the Ethereum bridge at height `l = 3400`, i.e. the first block of epoch `34`.

```json
{
    "content": {
        "title": "Launch the Ethereum bridge",
        "authors": "hello@heliax.dev",
        "discussions-to": "hello@heliax.dev",
        "created": "2023-01-01T08:00:00Z",
        "license": "Unlicense",
        "abstract": "Halt the chain and launch the Ethereum bridge at Namada block height 3400",
        "motivation": "",
    },
    "author": "hello@heliax.dev",
    "voting_start_epoch": 30,
    "voting_end_epoch": 33,
    "grace_epoch": 0,
}
```

- The governance proposal passes at block `3300`

- Putative Ethereum bridge smart contracts are deployed, with the proxy contract located at `0x00000000000000000000000000000000DeaDBeef`

- At block height `3400`, the chain halts

- The chain restarts with the governance parameter `eth_bridge_proxy_address` set to `0x00000000000000000000000000000000DeaDBeef`
