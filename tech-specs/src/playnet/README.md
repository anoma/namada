# Playnet

 🕹🎮👾 Welcome to the very first Anoma testnet and thank you for joining us! 🕹🎮👾 

The main goals of this testnet is to try out some of the functionality of the ledger, intent broadcaster and the matchmaker and to get some early feedback on its current state. To give feedback, ask questions and report issues, please use the #playnet Slack channel. Many issues and limitations are well known and our test coverage is currently very low, so please excuse Anoma while it is rough around the edges.

You can interact with Anoma via transactions, validity predicates and intents turned into transactions by the matchmaker. Because we don't have a proper wallet yet, each of us will have a pre-generated account address and a wallet key on the genesis block. Because all the keys are public, please respect others' keys and do not use them to sign stuff :)

## 📇 Addresses

The following are the addresses that we have included in the genesis block. You can add them to your shell to use them in commands. You should be able to find your own address among them:

```shell
TODO add user addresses once we have participants and their accounts prepared

# token addresses
export XAN=a1qq5qqqqqxuc5gvz9gycryv3sgye5v3j9gvurjv34g9prsd6x8qu5xs2ygdzrzsf38q6rss33xf42f3
export BTC=a1qq5qqqqq8q6yy3p4xyurys3n8qerz3zxxeryyv6rg4pnxdf3x3pyv32rx3zrgwzpxu6ny32r3laduc
export XTZ=a1qq5qqqqqx3z5xd3ngdqnzwzrgfpnxd3hgsuyx3phgfry2s3kxsc5xves8qe5x33sgdprzvjptzfry9
```

## ፨ The nodes

To run the ledger:
```shell
# TODO specify peers' addresses

anoma run-ledger
```

To run the intent broadcaster with the matchmaker that can submit transactions to the ledger:
```shell
# TODO specify peers' addresses and ledger's address if not local

anoma run-gossip --rpc \
  --matchmaker-path matchmaker_template/matchmaker.wasm \
  --tx-code-path txs/tx_from_intent/tx.wasm \
  --ledger-address "127.0.0.1:26657"
```

## 🧮 WASM

Currently, Anoma only supports wasm built from Rust code. This is used for validity predicates, transactions' code, matchmaker's logic and matchmaker's intent filter. We provide a prelude with functions specialized for each of these environments. Additionally, any library code that you may attempt to use in wasm has to be able to compile to wasm, which means no foreign function interface (e.g. C dependencies).

Because wasm doesn't have any built-in logging facilities nor access to stdout, trying to print from wasm has no effect. Instead, we provide `log_string` function in the wasm environment preludes. When the wasm is being executed, this will be printed from the node's log (search for `WASM Transaction log`, `WASM Validity predicate log` or `WASM Matchmaker log`). You can use the Rust's `format!` macro for the string that you want to print. Because we don't yet have an RPC client, this in combination with transactions' `--dry-run` flag is the best way to query the ledger's state.

To view the full list of functions available in wasm, please refer to:
- TODO host the built docs on github pages and update the links here
- [Transaction prelude](TODO)
- [Validity predicate prelude](TODO)
- [Matchmaker prelude](TODO)

## ☑️ Validity predicates

Your account will be instantiated with a validity predicate built from the source code of `vps/vp_user/src/lib.rs` and a public key. This VP allows:
- for anyone to send you a token(s)
- for you to send a token(s), which must be authorized by a signature with the key associated with your account
- perform any changes to your account's storage, which must also be authorized by a signature
- perform transactions created by the matchmaker from intents that were signed by your the key associated with your account

You can customize this code and deploy it to the ledger with a transaction described below.

## 📩 Transactions

A transaction consists of a wasm code and additional optional arbitrary data bytes. The data will be passed to the transaction as its input when it's being executed on-chain.

Any of the following commands can optionally be submitted with `--dry-run` argument to simulate transaction's execution without including it in a block.

### 💸 A simple token transfer

To make a transfer of e.g. `10.1` of a fungible token `$XAN` from `$ALICE` to `$BOB`:

```shell
anoma client transfer --source $ALICE \
  --target $BOB \
  --token $XAN \
  --amount 10.1 \
  --code-path txs/tx_transfer/tx.wasm
```

This client command will take care of signing the transaction using your key.

### ♼ Update an account's validity predicate

To update an account's validity predicate, you can customize the default user's VP at `vps/vp_user/src/lib.rs`, or built your own from scratch using `vps/vp_template/src/lib.rs`. To deploy to, use e.g.:

```shell
# Compile the validity predicate
make -C vps/vp_user

# Submit a transaction with the updated VP to the ledger
anoma client update --address $ALICE --code-path vps/vp_user/vp.wasm
```

### 🦄 A custom transaction

To submit a custom transaction, one can use the `txs/tx_template/src/lib.rs` to implement the transaction's effects. Optionally, you can attach arbitrary bytes to the transaction from a file with the `--data-path` argument.

For example:

```shell
# Compile the transaction's code from the template
make -C txs/tx_template

# Submit the transaction to the ledger
anoma client tx --code-path txs/tx_template/tx.wasm --data-path tx.data
```

This transaction is by default not signed by any key, so if you try to use it make changes to your account's storage, it will be rejected by your validity predicate.

## ✋ Intents

In general, intents are some data that describe what you'd like to do with your account. We provide a template for intents signed by the source key of the source address, which can describe a desire to trade one of the fungible tokens.

To create a file `intent.data` with the intent's data, use e.g.:

```shell
anoma client craft-intent --address $ALICE \
  --token-buy $XTZ \
  --amount-buy 10 \
  --token-sell $BTC \
  --amount-sell 20 \
  --file-path intent.data
```

To submit the intent from the file to the intent broadcaster (which will propagate to matchmakers):
```shell
# TODO specify a public intent broadcaster address

anoma client intent --node "http://[::1]:39111" \
  --data-path intent.data \
  --topic "asset_v0"
```

Once a matchmaker finds suitable matches of intents that it decides are likely to be accepted, it will try to submit a transaction to a connected ledger.

## 🤝 Matchmaker

The provide matchmaker's code tries to match intents using a graph of intents in the format described above constructed with Tarjan's algorithm, but it also allows for you to write your own! The source code to the matchmaker is at `matchmaker_template/src/lib.rs`. To customize the transaction's code that is used to submit transactions from matched intent, you can update `txs/tx_from_intent/src/lib.rs`.

```
# build the matchmaker's code
make -C matchmaker_template

# build the matchmaker's transaction's code
make -C txs/tx_from_intent
```

And then restart the matchmaker.
