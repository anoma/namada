# Upgrades
This page covers all installation steps required by various upgrades to testnets.


## Latest Upgrade

TBD


## Latest Testnet

***22/02/2023*** `public-testnet-4`

The testnet launches on 22/02/2023 at 17:00 UTC with the genesis validators from `public-testnet-4`. It launches with [version v0.14.1](https://github.com/anoma/namada/releases/tag/v0.14.1) and chain-id `TBD`. 
If your genesis transaction is contained in [this folder](https://github.com/anoma/namada-testnets/tree/main/namada-public-testnet-4), you are one of the genesis validators. In order for the testnet to come online at least 2/3 of those validators need to be online.

The installation docs are updated and can be found [here](./environment-setup.md). The running docs for validators/fullnodes can be found [here](./running-a-full-node.md).

## Previous upgrades:

***13/02/2023*** `public-testnet-3`

On *09/02/2023* the Namada chain `public-testnet-3` halted due to a bug in the Proof of Stake implementation when handling an edge case. Over the weekend, the team were able to fix and test a new patch that resolves the issue at hand. On *13/02/2023 11:30 UTC*, we were able to recover the network by having internal validators upgrade to the new patch. We are now calling on validators to upgrade to the new testnet as well, which will allow you to interact with the recovered chain.

**Upgrading**
1. Begin by stopping all instances of the namada node
```bash
killall namadan
```
2. Build the new tag (or download the binaries [here](https://github.com/anoma/namada/releases/tag/v0.13.4))
```bash
cd namada
export NAMADA_TAG=v0.13.4
make build-release
```
3. Copy the new binaries to path. More in depth instructions can be found at [here](./environment-setup.md)
4. Once this has been completed, **the node must tesync from genesis** (see below)

**How to resync from genesis:**
1. As a precautionary measure, make a backup of your pregenesis keys
```bash
mkdir backup-pregenesis && cp -r .namada/pre-genesis backup-pregenesis/
```
2. Delete the relevant folder in .namada
```bash
rm -r .namada/public-testnet-3.0.81edd4d6eb6
rm .namada/public-testnet-3.0.81edd4d6eb6.toml
```
WARNING: Do not delete the entire `.namada` folder, as it contains your pre-genesis keys. If this is accidentally done, you will have to copy over the backup-pregenesis file. See [these instructions](./run-your-genesis-validator.md) for more details
3. Rejoin the network
```bash
export CHAIN_ID="public-testnet-3.0.81edd4d6eb6"
namada client utils join-network \
--chain-id $CHAIN_ID --genesis-validator $ALIAS
```
4. Run the node. One can simply run the ledger again using the familiar command
```bash
  NAMADA_TM_STDOUT=true namada node ledger run
  ```

Please reach out with any questions if you have any. This upgrade can be done asynchronously, but if you wish to continue validating the chain and testing our features, you must execute the above steps.

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
