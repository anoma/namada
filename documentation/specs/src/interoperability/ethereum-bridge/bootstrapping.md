# Bootstrapping the bridge

## Overview

The Ethereum bridge may not be enabled at the launch (i.e. genesis) of a
Namada chain. To enable the Ethereum bridge, there are four governance
parameters which must be written to storage:

- `eth_bridge_min_confirmations` - The minimum number of block confirmations
  on Ethereum required for any given event to be voted on by Namada validators.
- `eth_bridge_bridge_address` - The address of the `Bridge` contract, used to
  perform transfers in either direction (Namada <> Ethereum).
- `eth_bridge_bridge_version` - The version of the `Bridge` contract, starting
  from 1.
- `eth_bridge_governance_address` - The address of the `Governance` contract,
  used to perform administrative tasks, such as updating validator sets in
  Ethereum.
- `eth_bridge_governance_version` - The version of the `Governance` contract,
  starting from 1.
- `eth_bridge_wnam_address` - The address of the deployment of the native
  ERC20 address, representing NAM in Ethereum.

An overview of the steps to follow, after genesis, to enable the Ethereum bridge
for a given Namada chain are:

1. A governance proposal should be held to agree on a block height `h` at which
   to launch the Ethereum bridge by means of a hard fork.
2. If the proposal passes, the Namada chain must halt after finalizing block
   `h-1`.
3. The [Ethereum bridge smart contracts](./ethereum_smart_contracts.md) are
   deployed to the relevant EVM chain, with the consensus validator set at block
   height `h` as the initial validator set that controls the bridge.
4. Details are published so that the deployed contracts can be verified by anyone
   who wishes to do so.
5. If consensus validators for block height `h` regard the deployment as valid, the
   chain should be restarted with a new genesis file that specifies
   the parameters described above.

At this point, the bridge is launched and it may start being used. Validators'
ledger nodes will immediately and automatically coordinate in order to craft the
first Bridge pool root's vote extension, used to prove the existence of a quorum
decision on the root of the merkle tree of transfers to Ethereum and its associated
nonce.

Conversely, if the bridge is already enabled during genesis, the same steps need
to be followed. Naturally, no restarting is required.

## Facets

### Governance proposal

The governance proposal can be freeform and simply indicate what the value of
`h` should be. Validators should then configure their nodes to halt at this
height. The `grace_epoch` is arbitrary as there is no code to be executed as
part of the proposal, instead validators must take action manually as soon as
the proposal passes. The block height `h` must be in an epoch that is strictly
greater than `voting_end_epoch`.

### Value for launch height `h`

The consensus validator set at the launch height chosen for starting the Ethereum
bridge will have the extra responsibility of restarting the chain if they
consider the deployed smart contracts as valid. For this reason, the validator
set at this height must be known in advance of the governance proposal
resolving, and a channel set up for offchain communication and co-ordination of
the chain restart. In practise, this means the governance proposal to launch the
chain should commit to doing so within an epoch of passing, so that the
validator set is definitely known in advance.

### Deployer

Once the smart contracts are fully deployed, only the consensus validator set for
block height `h` should have control of the contracts so in theory anyone could
do the Ethereum bridge smart contract deployment.

### Backing out of Ethereum bridge launch

If for some reason the validity of the smart contract deployment cannot be
agreed upon by the validators who will responsible for restarting Namada, it
must remain possible to restart the chain with the Ethereum bridge still not
enabled.

## Example

In this example, all epochs are assumed to be `100` blocks long, of equal duration
(in time), and the consensus validator set does not change at any point.

1. A governance proposal is made to launch the Ethereum bridge at height `h =
   3400`, i.e. the first block of epoch `34`.

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
    "grace_epoch": 33,
}
```

2. The governance proposal passes at block `3300` (the first block of epoch `33`).
3. Validators for epoch `33` manually configure their nodes to halt after having
   finalized block `3399`, before that block is reached.
4. The chain halts after having finalized block `3399` (the last block of epoch
   `33`).
5. Putative Ethereum bridge smart contracts are deployed at this point, with, e.g.
   the `Bridge` contract located at `0x00000000000000000000000000000000DeaDBeef`.
6. Verification of the Ethereum bridge smart contracts take place.
7. Validators coordinate to craft a new genesis file for the chain restart at
   `3400`, with the governance parameter `eth_bridge_governance_address` set to
   `0x00000000000000000000000000000000DeaDBeef`, `eth_bridge_wnam_address` at
   `0x000000000000000000000000000000000000Cafe`, etc.
8. The chain restarts at `3400` (the first block of epoch `34`).
