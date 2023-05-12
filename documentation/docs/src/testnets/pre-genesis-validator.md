## 2) Generate pre-genesis validator setup

1. Create a pre-genesis file inside the `namada` repository.
``` bash
cd namada
export ALIAS="CHOOSE_A_NAME_FOR_YOUR_VALIDATOR"
export PUBLIC_IP="LAPTOP_OR_SERVER_IP"
namada client utils init-genesis-validator --alias $ALIAS \
--max-commission-rate-change 0.01 --commission-rate 0.05 \
--net-address $PUBLIC_IP:26656
```
2. Expect the message:
- Linux: `Pre-genesis TOML written to /home/[your-username]/.config/namada/pre-genesis/[your-alias]/validator.toml`
- MacOS: `Pre-genesis TOML written to /Users/[your-username]/Library/Application Support/com.heliax.namada/pre-genesis/[your-alias]/validator.toml`

This will generate a folder inside `$HOME/.config/namada` or `$HOME/Library/Application\ Support/com.heliax.namada` depending on the operating system (OS). The former is based on a linux OS and the latter is based on a MacOS.

3. You can print the validator.toml by running: 

- Linux `cat $HOME/.config/namada/pre-genesis/$ALIAS/validator.toml`
- MacOS `cat $HOME/Library/Application\ Support/com.heliax.namada/pre-genesis/$ALIAS/validator.toml`


## 2.1) Submitting the config
If you want to be a genesis validator for the testnet, please make a pull request to https://github.com/anoma/namada-testnets adding your validator.toml file to the relevant directory (e.g. `namada-public-testnet-2` for the second public testnet), renaming it to `$alias.toml`. 

e.g. if you chose your alias to be "bertha", submit the file with the name `bertha.toml`. You can see what an example PR looks like [here](https://github.com/anoma/namada-testnets/pull/29).

## 2.2) Wait for the CHAIN_ID
Wait until corresponding `CHAIN_ID` has been distributed.
