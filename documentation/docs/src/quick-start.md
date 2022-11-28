# Quickstart - How to run a validator on Namada

## About this guide

This guide is for those interested in operating a Namada validator node and assumes basic knowledge of the terminal and how commands are used.

* Comments start with `#`:

```# this is a comment make sure you read them!```

* Sample outputs start with an arrow:
  
```➜ this is an example command line output useful for comparing```

## Installing Namada

See [the installation guide](user-guide/install.md) for details on installing the Namada binaries. Commands in this guide will assume you have the Namada binaries (`namada`, `namadan`, `namadaw`, `namadac`) on your $PATH.

A simple way to add these binaries to one's path is to run
```shell
cp namada/target/release/namada* /usr/local/bin/
```



## Joining a network

See [the testnets page](testnets) for details of how to join a testnet. The rest of this guide will assume you have joined a testnet chain using the `namadac utils join-network` command.

## Run a ledger node

We recommend this step with [tmux](https://www.hamvocke.com/blog/a-quick-and-easy-guide-to-tmux/), which allows the node to keep running without needing the terminal to be open indefinitely. If not, skip to the subsequent step.

```shell
tmux

# inside the tmux/or not

namada ledger

# can detach the tmux (Ctrl-B then D)
```

For a more verbose output, one can run 
```shell
export ANOMA_TM_STDOUT='true'
namada ledger
```

This should sync your node to the ledger and will take a while (depending on your computer). Subsequent commands (generating an account, etc.)  are unlikely to work until it is fully synced. Enquire the current block height with other participants to make sure you are synced in order to proceed.

## Account

Accounts on Namada are divided into two subcategories:
* Implicit accounts (all use the same Validity Predicate)
* Established accounts (can use a chosen Validity Predicate)

In order to make transactions on Namada, an account is required, and an implicit account can be created easily.

An implicit account can be generated from the commands described below

```shell
namadaw address gen \
  --alias example-implicit

➜ Enter encryption password: 
Successfully added a key and an address with alias: "example-implicit"

```
An implicit account with alias "example-implicit" has now been successfully generated and stored locally in the wallet.

It is possible to derive an Established Account through submitting a transaction, signing it with the key for the implicit account. Note that this transaction, as with any transaction on Namada, will consume "gas", and will require a positive balance of NAM tokens.

To initialize an account operator on-chain under the alias "example-established":

```shell
namadac init-account \
  --source example-implicit \
  --public-key example-implicit \
  --alias example-established

➜ Jan 06 22:22:19.864  INFO anoma_apps::cli::context: Chain ID: anoma-testnet-1.2.bf0181d9f7e0
Enter decryption password: 
Last committed epoch: 22386
Transaction added to mempool: Response { code: Ok, data: Data([]), log: Log("Mempool validation passed"), hash: transaction::Hash(9193C2B2C56AAB1B081B18DA0FBBD4B26C5EF7CEE4B35812ECCB1CC1D1443C45) }
Transaction applied with result: {
  "info": "Transaction is valid. Gas used: 6080310; Changed keys: #atest1v4ehgw36ggmyzwp5g9prgsekgsu5y32z8ycnsvpeggcnys35gv65yvzxg3zrjwphgcu5gde4lvmstw/?, #atest1v4ehgw36ggmyzwp5g9prgsekgsu5y32z8ycnsvpeggcnys35gv65yvzxg3zrjwphgcu5gde4lvmstw/ed25519_pk; VPs result: ",
  "height": "650627",
  "hash": "4FCCBCE5D4335C3A265B5CF22D5B8999451715F8146EB13194711B5EC70B612A",
  "code": "0",
  "gas_used": "6080310",
  "initialized_accounts": [
    "atest1v4ehgw36ggmyzwp5g9prgsekgsu5y32z8ycnsvpeggcnys35gv65yvzxg3zrjwphgcu5gde4lvmstw"
  ]
}
The transaction initialized 1 new account
➜ Added alias example-established for address atest1v4ehgw36ggmyzwp5g9prgsekgsu5y32z8ycnsvpeggcnys35gv65yvzxg3zrjwphgcu5gde4lvmstw
```

The "faucet" is a native established account on Namada that is willing to give a maximum of 1000 tokens to any user at request. Let's transfer ourselves `1000 NAM` from the faucet with the same alias using:

```shell
namadac transfer \
  --source faucet \
  --target example-established \
  --token NAM \
  --amount 1000 \
  --signer example-established

➜ Jan 06 22:24:32.926  INFO anoma_apps::cli::context: Chain ID: anoma-testnet-1.2.bf0181d9f7e0
➜ Looking-up public key of atest1v4ehgw36ggmyzwp5g9prgsekgsu5y32z8ycnsvpeggcnys35gv65yvzxg3zrjwphgcu5gde4lvmstw from the ledger...
Enter decryption password: 
Last committed epoch: 22388
Transaction added to mempool: Response { code: Ok, data: Data([]), log: Log("Mempool validation passed"), hash: transaction::Hash(3A5CA1790FDF5150EF1478DE1E3B2D2F7189B0E5D396176E5E5BFC7A37C58D00) }
Transaction applied with result: {
  "info": "Transaction is valid. Gas used: 1504228; Changed keys: #atest1v4ehgw36x3prswzxggunzv6pxqmnvdj9xvcyzvpsggeyvs3cg9qnywf589qnwvfsg5erg3fkl09rg5/balance/#atest1v4ehgw36ggmyzwp5g9prgsekgsu5y32z8ycnsvpeggcnys35gv65yvzxg3zrjwphgcu5gde4lvmstw, #atest1v4ehgw36x3prswzxggunzv6pxqmnvdj9xvcyzvpsggeyvs3cg9qnywf589qnwvfsg5erg3fkl09rg5/balance/#atest1v4ehgw36gc6yxvpjxccyzvphxycrxw2xxsuyydesxgcnjs3cg9znwv3cxgmnj32yxy6rssf5tcqjm3; VPs result:  Accepted: atest1v4ehgw36ggmyzwp5g9prgsekgsu5y32z8ycnsvpeggcnys35gv65yvzxg3zrjwphgcu5gde4lvmstw, atest1v4ehgw36gc6yxvpjxccyzvphxycrxw2xxsuyydesxgcnjs3cg9znwv3cxgmnj32yxy6rssf5tcqjm3, atest1v4ehgw36x3prswzxggunzv6pxqmnvdj9xvcyzvpsggeyvs3cg9qnywf589qnwvfsg5erg3fkl09rg5;",
  "height": "650706",
  "hash": "26AAE9D79F62EE8E62108D8D7689F4FFF12EA613AF29C7D4CDBEA999C28C6224",
  "code": "0",
  "gas_used": "1504228",
  "initialized_accounts": []
}
```

To query the balance of your account "example-established":

```shell
namadac balance \
  --owner example-established
```

## Setting up the validator node

Initialize a validator account under any alias - in this example, "example-validator":

```shell
namadac init-validator \
  --alias example-validator \
  --source example-established

➜  Jan 06 22:26:29.927  INFO anoma_apps::cli::context: Chain ID: anoma-testnet-1.2.bf0181d9f7e0
Generating validator account key...
```

You will be asked to enter encryption passwords to generate a validator account key, consensus key and a staking reward account key. After entering the encryption password and a decryption password for the "example-established" account's key, the transaction should be added to the mempool and applied in a future block.

```shell
➜ Transaction added to mempool: Response { code: Ok, data: Data([]), log: Log("Mempool validation passed"), hash: transaction::Hash(F61D3D73CE7EFCC2021940A75B713C499D4942F820F6EC0F7924B70E7F2E751A) }
Transaction applied with result: {
  "info": "Transaction is valid. Gas used: 15139451; Changed keys: #atest1v9hx7w362pex7mmxyphkvgznw3skkefqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqq8ylv7/validator/#atest1v4ehgw36g3prx3pjxapyvve3xvury3fkxg6nqsesxccnzw2rxdryg335xcmnysjzxdzyvd2pamfmwd/voting_power, #atest1v9hx7w362pex7mmxyphkvgznw3skkefqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqq8ylv7/validator/#atest1v4ehgw36g3prx3pjxapyvve3xvury3fkxg6nqsesxccnzw2rxdryg335xcmnysjzxdzyvd2pamfmwd/staking_reward_address, #atest1v4ehgw36xppnjsjzx4ryxs2zgc6nx33hxpq5zve4g5u5xdjpgfz5xv2pg3ryy3zrxyenssfcxn02yg/ed25519_pk, #atest1v9hx7w362pex7mmxyphkvgznw3skkefqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqq8ylv7/validator/#atest1v4ehgw36g3prx3pjxapyvve3xvury3fkxg6nqsesxccnzw2rxdryg335xcmnysjzxdzyvd2pamfmwd/total_deltas, #atest1v9hx7w362pex7mmxyphkvgznw3skkefqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqq8ylv7/validator/#atest1v4ehgw36g3prx3pjxapyvve3xvury3fkxg6nqsesxccnzw2rxdryg335xcmnysjzxdzyvd2pamfmwd/state, #atest1v9hx7w362pex7mmxyphkvgznw3skkefqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqq8ylv7/validator/#atest1v4ehgw36g3prx3pjxapyvve3xvury3fkxg6nqsesxccnzw2rxdryg335xcmnysjzxdzyvd2pamfmwd/consensus_key, #atest1v4ehgw36g3prx3pjxapyvve3xvury3fkxg6nqsesxccnzw2rxdryg335xcmnysjzxdzyvd2pamfmwd/?, #atest1v4ehgw36xppnjsjzx4ryxs2zgc6nx33hxpq5zve4g5u5xdjpgfz5xv2pg3ryy3zrxyenssfcxn02yg/?, #atest1v9hx7w362pex7mmxyphkvgznw3skkefqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqq8ylv7/validator_set, #atest1v4ehgw36g3prx3pjxapyvve3xvury3fkxg6nqsesxccnzw2rxdryg335xcmnysjzxdzyvd2pamfmwd/ed25519_pk, #atest1v9hx7w362pex7mmxyphkvgznw3skkefqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqq8ylv7/address_raw_hash/DB3D27BF31382E6250C06119C3FDF4672BB3DF5A; VPs result:  Accepted: atest1v9hx7w362pex7mmxyphkvgznw3skkefqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqq8ylv7;",
  "height": "650779",
  "hash": "3B6AA8F3E6F1951E21703CABA4CCD24F82F6D5C38674041A7AAA1B7227B1E6B8",
  "code": "0",
  "gas_used": "15139451",
  "initialized_accounts": [
    "atest1v4ehgw36xppnjsjzx4ryxs2zgc6nx33hxpq5zve4g5u5xdjpgfz5xv2pg3ryy3zrxyenssfcxn02yg",
    "atest1v4ehgw36g3prx3pjxapyvve3xvury3fkxg6nqsesxccnzw2rxdryg335xcmnysjzxdzyvd2pamfmwd"
  ]
}
Added alias example-validator for address atest1v4ehgw36g3prx3pjxapyvve3xvury3fkxg6nqsesxccnzw2rxdryg335xcmnysjzxdzyvd2pamfmwd.
Added alias example-validator-rewards for address atest1v4ehgw36xppnjsjzx4ryxs2zgc6nx33hxpq5zve4g5u5xdjpgfz5xv2pg3ryy3zrxyenssfcxn02yg.

The validator's addresses and keys were stored in the wallet:
  Validator address "example-validator"
  Staking reward address "example-validator-rewards"
  Validator account key "example-validator-key"
  Consensus key "example-validator-consensus-key"
  Staking reward key "example-validator-rewards-key"
The ledger node has been setup to use this validator's address and consensus key.
```

Once the `init-validator` transaction is applied in the block and the on-chain generated validator's address is stored in your wallet, you MUST restart the `namada ledger` node to start the node as a validator that you've just created.

When you restart the node, you might notice log message "This node is not a validator" from Tendermint. This is expected, because your validator doesn't yet have any stake in the [PoS system](./user-guide/ledger/pos.md).

We will now add some stake to your validator account.

Transfer 1000 NAM to your validator account ("example-validator"):

```shell
namadac transfer \
  --source example-established \
  --target example-validator \
  --token NAM \
  --amount 1000
```

```shell
➜  Jan 06 22:28:17.624  INFO anoma_apps::cli::context: Chain ID: anoma-testnet-1.2.bf0181d9f7e0
Looking-up public key of atest1v4ehgw36ggmyzwp5g9prgsekgsu5y32z8ycnsvpeggcnys35gv65yvzxg3zrjwphgcu5gde4lvmstw from the ledger...
Enter decryption password: 
Last committed epoch: 22392
Transaction added to mempool: Response { code: Ok, data: Data([]), log: Log("Mempool validation passed"), hash: transaction::Hash(7FD43C7573B4A62E24DBB6C99EE6C7A107DF01CC5F947517B91742E6324AE58D) }
Transaction applied with result: {
  "info": "Transaction is valid. Gas used: 1989091; Changed keys: #atest1v4ehgw36x3prswzxggunzv6pxqmnvdj9xvcyzvpsggeyvs3cg9qnywf589qnwvfsg5erg3fkl09rg5/balance/#atest1v4ehgw36g3prx3pjxapyvve3xvury3fkxg6nqsesxccnzw2rxdryg335xcmnysjzxdzyvd2pamfmwd, #atest1v4ehgw36x3prswzxggunzv6pxqmnvdj9xvcyzvpsggeyvs3cg9qnywf589qnwvfsg5erg3fkl09rg5/balance/#atest1v4ehgw36ggmyzwp5g9prgsekgsu5y32z8ycnsvpeggcnys35gv65yvzxg3zrjwphgcu5gde4lvmstw; VPs result:  Accepted: atest1v4ehgw36g3prx3pjxapyvve3xvury3fkxg6nqsesxccnzw2rxdryg335xcmnysjzxdzyvd2pamfmwd, atest1v4ehgw36ggmyzwp5g9prgsekgsu5y32z8ycnsvpeggcnys35gv65yvzxg3zrjwphgcu5gde4lvmstw, atest1v4ehgw36x3prswzxggunzv6pxqmnvdj9xvcyzvpsggeyvs3cg9qnywf589qnwvfsg5erg3fkl09rg5;",
  "height": "650842",
  "hash": "D251AAB5D4CD9471DB4E11DA09DEF0F15E2A3EC95EE0EE2C76766839FC352394",
  "code": "0",
  "gas_used": "1989091",
  "initialized_accounts": []
}
```

Bond the 1000 NAM to "example-validator" using:

```shell
namadac bond \
  --validator example-validator \
  --amount 1000
```



```shell
➜ Jan 06 22:29:08.903  INFO anoma_apps::cli::context: Chain ID: anoma-testnet-1.2.bf0181d9f7e0
Looking-up public key of atest1v4ehgw36g3prx3pjxapyvve3xvury3fkxg6nqsesxccnzw2rxdryg335xcmnysjzxdzyvd2pamfmwd from the ledger...
Enter decryption password: 
Last committed epoch: 22393
Transaction added to mempool: Response { code: Ok, data: Data([]), log: Log("Mempool validation passed"), hash: transaction::Hash(2B814FE404F6F1D8C07CC3A51AA3038C193810251B9C50107B79698ED15A4EDC) }
Transaction applied with result: {
  "info": "Transaction is valid. Gas used: 3734939; Changed keys: #atest1v9hx7w362pex7mmxyphkvgznw3skkefqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqq8ylv7/validator/#atest1v4ehgw36g3prx3pjxapyvve3xvury3fkxg6nqsesxccnzw2rxdryg335xcmnysjzxdzyvd2pamfmwd/total_deltas, #atest1v9hx7w362pex7mmxyphkvgznw3skkefqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqq8ylv7/total_voting_power, #atest1v9hx7w362pex7mmxyphkvgznw3skkefqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqq8ylv7/validator_set, #atest1v4ehgw36x3prswzxggunzv6pxqmnvdj9xvcyzvpsggeyvs3cg9qnywf589qnwvfsg5erg3fkl09rg5/balance/#atest1v4ehgw36g3prx3pjxapyvve3xvury3fkxg6nqsesxccnzw2rxdryg335xcmnysjzxdzyvd2pamfmwd, #atest1v4ehgw36x3prswzxggunzv6pxqmnvdj9xvcyzvpsggeyvs3cg9qnywf589qnwvfsg5erg3fkl09rg5/balance/#atest1v9hx7w362pex7mmxyphkvgznw3skkefqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqq8ylv7, #atest1v9hx7w362pex7mmxyphkvgznw3skkefqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqq8ylv7/validator/#atest1v4ehgw36g3prx3pjxapyvve3xvury3fkxg6nqsesxccnzw2rxdryg335xcmnysjzxdzyvd2pamfmwd/voting_power, #atest1v9hx7w362pex7mmxyphkvgznw3skkefqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqq8ylv7/bond/#atest1v4ehgw36g3prx3pjxapyvve3xvury3fkxg6nqsesxccnzw2rxdryg335xcmnysjzxdzyvd2pamfmwd/#atest1v4ehgw36g3prx3pjxapyvve3xvury3fkxg6nqsesxccnzw2rxdryg335xcmnysjzxdzyvd2pamfmwd; VPs result:  Accepted: atest1v4ehgw36g3prx3pjxapyvve3xvury3fkxg6nqsesxccnzw2rxdryg335xcmnysjzxdzyvd2pamfmwd, atest1v9hx7w362pex7mmxyphkvgznw3skkefqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqq8ylv7, atest1v4ehgw36x3prswzxggunzv6pxqmnvdj9xvcyzvpsggeyvs3cg9qnywf589qnwvfsg5erg3fkl09rg5;",
  "height": "650869",
  "hash": "14F5C67D27E2F9695EA40ABEA2DEC69F5B0FFEF5DFD7CB7D0FC397CC8A618BA8",
  "code": "0",
  "gas_used": "3734939",
  "initialized_accounts": []
}
```

Check your bond:

```shell
namadac bonds \
  --validator example-validator

➜ Jan 06 22:30:42.798  INFO anoma_apps::cli::context: Chain ID: anoma-testnet-1.2.bf0181d9f7e0
Last committed epoch: 22394
Self-bonds:
  Active from epoch 22395: Δ 1000
Bonds total: 1000
```

Check the voting power - this will be 0 until the active-from epoch is reached (in this case `22395`):

```shell
namadac voting-power \
  --validator example-validator

➜ Jan 06 22:31:24.908  INFO anoma_apps::cli::context: Chain ID: anoma-testnet-1.2.bf0181d9f7e0
Last committed epoch: 22395
Validator atest1v4ehgw36g3prx3pjxapyvve3xvury3fkxg6nqsesxccnzw2rxdryg335xcmnysjzxdzyvd2pamfmwd is active, voting power: 1
Total voting power: 44
```

Note that with the above command, you can also specify `--epoch` argument to check a future epoch.

Congratulations, you have set up a validator node!
