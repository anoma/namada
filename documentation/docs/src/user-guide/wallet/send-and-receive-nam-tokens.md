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