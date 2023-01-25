# Upgrades
This page covers all installation steps required by various upgrades to testnets.

## Latest Upgrade

### Hotfix for Testnet `public-testnet-2.1.4014f207f6d`

***25/01/2023***

At around 06:15 UTC 25/01/2023, a validator with very little stake was scheduled to become part of the active validator set. From this tx, we discovered a conversion bug between the Namada state machine and Tendermint, which lead to a crash in the node.
A patch was released [v0.13.3](https://github.com/anoma/namada/releases/tag/v0.13.3) in order to deal with this issue.

In order to successfully update your node, please follow the below steps:
1. Validators need to stop their node (`^c`)
2. Upgrade their version to v0.13.3 
3. Restart their node with the following `--time` argument:
```bash!
NAMADA_TM_STDOUT=true namadan ledger run --time 2023-01-25T18:00:00Z
```


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