# Genesis validator setup

A genesis validator is one which is a validator right from the first block of the chain - i.e. at genesis. The details of genesis validators are hardcoded into the genesis file that is distributed to all users who want to interact with a chain.

### Prerequisites

- a machine that meets the [requirements](../user-guide/install/hardware.md) for running a validator node
- an associated public IPv4 address with ports 26656 reachable from anywhere for P2P connections

## Pre-genesis

To setup all the [required keys](#required-keys) for a genesis validator for an upcoming network, you can execute the following command with an alias of your choice. Note that this alias is public (the address of your validator account will be visible in every wallet) and must be unique within the network.

You must also provide a static `{IP:port}` to the `--net-address` argument of your future node's P2P address.

### 1. Create your validator keys:
``` bash
export ALIAS="CHOOSE_A_NAME_FOR_YOUR_VALIDATOR"
export PUBLIC_IP="LAPTOP_OR_SERVER_IP"
namada client utils init-genesis-validator --alias $ALIAS \
--max-commission-rate-change 0.01 --commission-rate 0.05 \
--net-address $PUBLIC_IP:26656
```

### 2. After generating your keys, the command will print something like this:

```admonish note
If you have set the variable $XDG_DATA_HOME this is where the pre-genesis TOML will be written to. Otherwise see below for the default locations.
```

#### Linux 
```shell
Pre-genesis TOML written to $HOME/.local/share/namada
```
#### MacOS
```shell
Pre-genesis TOML written to /Users/$USER/Library/Application\ Support/Namada
```

### 3. Save this directory as an environment variable for later use:

#### Linux 
```shell
export BASE_DIR="$HOME/.local/share/namada"
```
#### MacOS
```shell
export BASE_DIR="/Users/$USER/Library/Application\ Support/Namada"
```

This file is the public configuration of your validator. You can safely share this file with the network's organizer, who is responsible for setting up and publishing the finalized genesis file and Namada configuration for the chain.

Note that the wallet containing your private keys will also be written into this directory.

### 4. You can print the validator.toml by running: 

### Linux 
`cat $HOME/.local/share/namada/pre-genesis/$ALIAS/validator.toml`
### MacOS 
`cat $HOME/Library/Application\ Support/Namada/pre-genesis/$ALIAS/validator.toml`

## Required keys

- Account key: Can be used to sign transactions that require authorization in the default validator validity predicate, such as a balance transfer.
- Staking rewards key: Can be used to sign transactions on the PoS staking rewards account.
- Protocol key: This key is used by the validator's ledger itself to sign protocol transaction on behalf of the validator.
- DKG key: Special key needed for participation in the DKG protocol
- Consensus key: Used in Tendermint consensus layer. Currently, this key is written to a file which is read by Tendermint.
- Tendermint node key: This key is used to derive Tendermint node ID for P2P connection authentication. This key is also written to a file which is read by Tendermint.
