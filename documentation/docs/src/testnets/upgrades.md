# Upgrades
This page covers all installation steps required by various upgrades to testnets.

## Latest Testnet

***06/02/2023*** `public-testnet-3`

The testnet launches on 09/02/2023 at 17:00 UTC with the genesis validators from `public-testnet-3`. It launches with [version v0.13.3](https://github.com/anoma/namada/releases/tag/v0.13.3) and chain-id `TBD`. 
If your genesis transaction is contained in [this folder](https://github.com/anoma/namada-testnets/tree/main/namada-public-testnet-3), you are one of the genesis validators. In order for the testnet to come online at least 2/3 of those validators need to be online.

The installation docs are updated and can be found [here](./environment-setup.md). The running docs for validators/fullnodes can be found [here](./running-a-full-node.md).

## Previous upgrades:

### Hotfix for Testnet `public-testnet-2.1.4014f207f6d`

***27/01/2023***

The hotfixed testnet ran during the week, when a strange bug caused the network to stall. The core team spent 1 week investigating the cause of the bug, and the result they found was quite interesting. If you are curious about the specific details of the bug, please have a read through Ray's blog post [here](https://blog.namada.net/explaining-the-namada-0-13-3-consensus-fork/). 

***25/01/2023***

At around 06:15 UTC 25/01/2023, a validator with very little stake was scheduled to become part of the active validator set. From this tx, we discovered a conversion bug between the Namada state machine and Tendermint, which lead to a crash in the node.
A patch was released [v0.13.3](https://github.com/anoma/namada/releases/tag/v0.13.3) in order to deal with this issue.


***23/01/2023***

A new testnet was released before the fortnightly testnet release schedule due to the below hardfork not working as intended. Follow the steps in [setting up a new testnet](./environment-setup.md)

### Hardfork v0.13.1

This hardfork is set to be instantiated at block height `37370`, which is predicted to occur at around 17.00 UTC on 18/01/2023.

**Requirements to do before 17.00 UTC 18/01/2023**

In order to install this upgrade, a user or validator must 

1. [Download the binaries](https://github.com/anoma/namada/releases/tag/v0.13.1-hardfork) or install them [from source](https://github.com/anoma/namada/releases/tag/v0.13.1-hardfork)

2. Ensure the versions are correct, such that `<PATH_TO_BINARY>/namada --version` is `v0.13.1-hardfork` 

3. Interrupt the `namada ledger` by the interrupt command `^C`

4. Install the binaries onto `$PATH` (this depends on your machine). This must be done after interrupting the ledger, as otherwise an error is likely to be thrown.

5. As soon as possible, restart the ledger by running `NAMADA_TM_STDOUT=true namada node ledger run`

The ledger will then update correctly at the correct height. In order to ensure a smooth fork, please do this as soon as possible.
