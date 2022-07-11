# Namada Wallet Guide

This document describes the different wallet concepts and options that are available to users of Namada who want to be able to [send, receive and interact](#send-and-receive-tokens) with NAM tokens on the Namada blockchain.

Check out the different options to generate a wallet:
- File System Wallet
- Paper Wallet
- Hardware Wallet

## Manage keypairs

Namada uses ed25519 keypairs for signing cryptographic operations on the blockchain.

To manage your keys, various sub-commands are available under:

```shell
anoma wallet key
```

### Generate a keypair

Generate a keypair with a given alias and derive the implicit address from its public key:

```shell
anoma wallet key gen --alias my-key
```

Note that the derived implicit address shares the same `my-key` alias. The previous command has the same effect as `anoma wallet address gen --alias my-key`.

### List all known keys

```shell
anoma wallet key list
```

## Manage addresses

All accounts in Namada have an unique address, exactly one Validity Predicate and optionally any additional data in its dynamic storage sub-space.

There are currently 3 types of account addresses:

- **Established:** Used for accounts that allow the deployment of custom validation logic. These must be created on-chain via a transaction (see [the Ledger guide](./ledger.md#-initialize-an-account)). The address is generated on-chain and is not known until the transaction is applied.
- **Implicit *(not fully supported yet)*:** Derived from your kepair, it can be used to authorize certain transactions from the account. They can be used as recipients of transactions even if the account has not been used on-chain before.
- **Internal:** Special internal accounts, such as protocol parameters account, PoS and IBC.

To manage addresses, similar to keys, various sub-commands are available:

```shell
anoma wallet address
```

### Generate an implicit address

```shell
anoma wallet address gen --alias my-account
```

Note that this will also generate and save a key from which the address was derived and save it under the same `my-account` alias. Thus, this command has the same effect as `anoma wallet key gen --alias my-account`.

### List all known addresses

```shell
anoma wallet address list
```

## File System Wallet

By default, the Namada Wallet is stored under `.anoma/{chain_id}/wallet.toml` where keys are stored encrypted. You can change the default base directory path with `--base-dir` and you can allow the storage of unencrypted keypairs with the flag `--unsafe-dont-encrypt`. 

If the wallet doesn't already exist, it will be created for you as soon as you run a command that tries to access the wallet. A newly created wallet will be pre-loaded with some internal addresses like `pos`, `pos_slash_pool`, `masp` and more. 

Currently, the Namada client can load the password via:

- Stdin: the client will prompt for a password.
- Env variable: by exporting a ENV variable called `ANOMA_WALLET_PASSWORD` with value of the actual password.
- File: by exporting an ENV variable called `ANOMA_WALLET_PASSWORD_FILE` with value containing the path to a file containing the password.

## Paper Wallet

At the moment, the Namada CLI doesn't provide a Paper Wallet.

## Hardware Wallet

The Ledger Hardware Wallet is currently in development.

## Send and Receive NAM tokens

### Initialize an established account

If you already have a key in your wallet, you can skip this step. Otherwise, [generate a new keypair](#generate-a-keypair) now.

Then, send a transaction to initialize your new established account and save its address with the alias `my-new-acc`. The `my-key` public key will be written into the account's storage for authorizing future transactions. We also sign this transaction with `my-key`.

```shell
anoma client init-account \
  --alias my-new-acc \
  --public-key my-key \
  --source my-key
```

Once this transaction has been applied, the client will automatically see the new address created by the transaction and add it to your Wallet with the chosen alias `my-new-acc`.

This command uses the prebuilt [User Validity Predicate](https://github.com/anoma/namada/blob/namada/wasm/wasm_source/src/vp_user.rs).

## Token transactions and queries

In Namada, tokens are implemented as accounts with a token validity predicate. It checks that its total supply is preserved in any transaction that uses this token. Your wallet will be pre-loaded with some token addresses that are initialized in the genesis block.

You can see the tokens addresses known by the client when you query all tokens balances:

```shell
anoma client balance
```

NAM is Namada's native token. To obtain some tokens in a testnet, there is a special "faucet" account that allows anyone to withdraw up to 1000 of any token for a single transaction. You can find the address of this account in your wallet. To get some tokens from the faucet account:

```shell
anoma client transfer \
  --source faucet \
  --target my-new-acc \
  --signer my-new-acc \
  --token NAM \
  --amount 1000
```

Note that because you don't have the key to sign a transfer from the faucet account, in the command above, we set the `--signer` explicitly to your account's address.

To submit a regular token transfer from your account to the `validator-1` address:

```shell
anoma client transfer \
  --source my-new-acc \
  --target validator-1 \
  --token NAM \
  --amount 10
```

This command will attempt to find and use the key of the source address to sign the transaction.

To query token balances for a specific token and/or owner:

```shell
anoma client balance --token NAM --owner my-new-acc
```

Note that for any client command that submits a transaction (`init-account`, `transfer`, `tx`, `update` and [PoS transactions](ledger/pos.md)), you can use the `--dry-run` flag to simulate the transaction being applied in the block, to see what its result would be.