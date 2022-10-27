# Namada Wallet Guide

This document describes the different wallet concepts and options that are available to users of Namada who want to be able to [send, receive and interact](#send-and-receive-nam-tokens) with NAM tokens on the Namada blockchain.


<!-- I want to either hyperlink or delete the below. I don't understand-->

Check out the different options to generate a wallet:

- File System Wallet
- Web Wallet
- Paper Wallet
- Hardware Wallet

## Manage keypairs

Namada uses [ed25519](https://en.wikipedia.org/wiki/EdDSA#Ed25519) keypairs for signing cryptographic operations on the blockchain.

To manage your keys, various sub-commands are available under:

```shell
namada wallet key
```

### Generate a keypair

It is possible to generate keys using the CLI. Generate a keypair with a given alias and derive the implicit address from its public key:

```shell
namada wallet key gen --alias my-key
```

```admonish note
The derived implicit address shares the same `my-key` alias. The previous command has the same effect as `namada wallet address gen --alias my-key`.
```

### List all known keys

```shell
namada wallet key list
```

## Manage addresses

All accounts in Namada have an unique address, exactly one Validity Predicate and optionally any additional data in its dynamic storage sub-space.

There are currently 3 types of account addresses:

- **Established:** Used for accounts that allow the deployment of custom validation logic. These must be created on-chain via a transaction (e.g. [initialize an account](#initialize-an-established-account)). The address is generated on-chain and is not known until the transaction is applied.
- **Implicit *(not fully supported yet)*:** Derived from your kepair, it can be used to authorize certain transactions from the account. They can be used as recipients of transactions even if the account has not been used on-chain before.
- **Internal:** Special internal accounts, such as protocol parameters account, PoS and IBC.

To manage addresses, similar to keys, various sub-commands are available:

```shell
namada wallet address
```

### Generate an implicit address

```shell
namada wallet address gen --alias my-account
```

```admonish note

Note that this will also generate and save a key from which the address was derived and save it under the same `my-account` alias. Thus, this command has the same effect as `namada wallet key gen --alias my-account`.
```

### List all known addresses

```shell
namada wallet address list
```

## File System Wallet

By default, the Namada Wallet is stored under `.anoma/{chain_id}/wallet.toml` where keys are stored encrypted. You can change the default base directory path with `--base-dir` and you can allow the storage of unencrypted keypairs with the flag `--unsafe-dont-encrypt`.

If the wallet doesn't already exist, it will be created for you as soon as you run a command that tries to access the wallet. A newly created wallet will be pre-loaded with some internal addresses like `pos`, `pos_slash_pool`, `masp` and more.

Currently, the Namada client can load the password via:

- **Stdin:** the client will prompt for a password.
- **Env variable:** by exporting a ENV variable called `ANOMA_WALLET_PASSWORD` with value of the actual password.
- **File:** by exporting an ENV variable called `ANOMA_WALLET_PASSWORD_FILE` with value containing the path to a file containing the password.

## Web Wallet

The Web Wallet for Namada is currently in closed beta.

## Paper Wallet

At the moment, the Namada CLI doesn't provide a Paper Wallet.

## Hardware Wallet

The Ledger Hardware Wallet is currently in development.

## Send and Receive NAM tokens

In Namada, tokens are implemented as accounts with the [Token Validity Predicate](https://github.com/anoma/namada/blob/namada/wasm/wasm_source/src/vp_token.rs). It checks that its total supply is preserved in any transaction that uses this token. Your wallet will be pre-loaded with some token addresses that are initialized in the genesis block.

### Initialize an established account

If you already have a key in your wallet, you can skip this step. Otherwise, [generate a new keypair](#generate-a-keypair) now.

Then, send a transaction to initialize your new established account and save its address with the alias `my-new-acc`. The `my-key` public key will be written into the account's storage for authorizing future transactions. We also sign this transaction with `my-key`.

```shell
namada client init-account \
  --alias my-new-acc \
  --public-key my-key \
  --source my-key
```

Once this transaction has been applied, the client will automatically see the new address created by the transaction and add it to your Wallet with the chosen alias `my-new-acc`.

This command uses the prebuilt [User Validity Predicate](https://github.com/anoma/namada/blob/namada/wasm/wasm_source/src/vp_user.rs).

### Send a Payment

To submit a regular token transfer from your account to the `validator-1` address:

```shell
namada client transfer \
  --source my-new-acc \
  --target validator-1 \
  --token NAM \
  --amount 10
```

This command will attempt to find and use the key of the source address to sign the transaction.

### See your balance

To query token balances for a specific token and/or owner:

```shell
namada client balance --token NAM --owner my-new-acc
```

```admonish note
For any client command that submits a transaction (`init-account`, `transfer`, `tx`, `update` and [PoS transactions](ledger/pos.md)), you can use the `--dry-run` flag to simulate the transaction being applied in the block and see what would be the result.

```

### See every known addresses' balance

You can see the token's addresses known by the client when you query all tokens balances:

```shell
namada client balance
```
