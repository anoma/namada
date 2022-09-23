# Internal Testnet 1

>⚠️ the values below might change frequently.

Latest values regarding the testnet that would be useful to have in your shell:

```shell
export NAMADA_TESTNET_CHAIN_ID='anoma-masp-0.3.51d2f83a8412b95'
export NAMADA_TESTNET_BRANCH='internal/testnet-n1'
export NAMADA_TESTNET_COMMIT='0184e64e044366ec370d1431ddf4691b4bd3a5b4'
```

## Installing Namada

You can install Namada by following the instructions from the [Install User Guide](../user-guide/install.md). Note that the binaries should be built from `$NAMADA_TESTNET_BRANCH` rather than `master` or a release tag like `v0.5.0`.

## Setting up Namada

At this point, depending on your installation choice, we will assume that the `namada` binaries are available on path and built from the latest testnet branch.

### Join a network

To join the current testnet, you need to download the configuration files. This can be done easily with:

```shell
namadac utils join-network --chain-id $NAMADA_TESTNET_CHAIN_ID
```

It should output something like this where the chain id might differ:

```shell
Downloading config release from https://github.com/heliaxdev/anoma-network-config/releases/download/anoma-masp-0.3.51d2f83a8412b95/anoma-masp-0.3.51d2f83a8412b95.tar.gz ...
Successfully configured for chain ID anoma-masp-0.3.51d2f83a8412b9`
```

The above command downloads the folder `.anoma` which contains a global config file `global-config.toml`; the genesis file for the specified chain id `{chain-id}.toml` and its corresponding configuration folder `{chain-id}` which contains the checksums for the wasm files under `wasm` and the p2p config `config.toml`.

### Setup the MASP parameters

Namada uses a multi-asset shielded pool (MASP) to enable private transfers. The pool relies on three circuits which require each individually their randomly generated parameters to work.

>⚠️ Normally, the parameters are downloaded through the `masp` crate by the client, but in case of troubles you should get them from someone in the team and follow the instructions below.

<!-- You can download the parameters with:
```shell
[command]
``` -->

The parameters need to be extracted to the correct folder where the node will read the parameters from.

**Ubuntu**

```shell
mkdir ~/.masp-params
tar -xvf masp-params.tar.gz ~/.masp-params
```

**Mac**

```shell
mkdir ~/Library/Application\ Support/MASPParams/
tar -xvf masp-params.tar.gz ~/Library/Application\ Support/MASPParams/
```

### Start a node

At this point, you are ready to start your Namada node with:

```shell
namada ledger
```

To keep your node running after closing your terminal, you can optionally use a terminal multiplexer like `tmux`.

## Using Namada

### Shielded transfers

Shielded balances are owned by a particular spending key. In this
testnet, spending keys are just arbitrary hexadecimal strings, provided
on the command line.

To try out shielded transfers, you will first need an ordinary
transparent account with some token balance. Example commands for that:

```
namadaw address gen --alias my-implicit
namadac init-account --source my-implicit --public-key my-implicit --alias my-established
namadac transfer --token btc --amount 1000 --source faucet --target my-established --signer my-established
```

The testnet tokens which the faucet can provide you are named `NAM`,
`BTC`, `ETH`, `DOT`, `Schnitzel`, `Apfel`, and `Kartoffel`. The faucet
will transfer these in increments of 1000 at a time.

Once you have an ordinary transparent account with some tokens, you
should select a spending key to hold your shielded balances. This is
just some hexadecimal string, like `1234`, `abcd`, or
`030cdcc0a43765d4645e22adbf9944b58c646d162c9a08890a08cc49a9580c9e`. Try
to select one that is unique to you (i.e., probably don't use `1234`);
you could randomly generate one with e.g. `openssl rand -hex 32`. The
wallet does not yet support spending keys, so make a note of yours
somewhere.

Shielded transfers work with the `namadac transfer` command, but either
`--source`, `--target`, or both are replaced. `--source` may be replaced
with `--spending-key` to spend a shielded balance, but if you are
following along, you don't have a shielded balance to spend yet.
`--target` may be replaced with `--payment-address` to create a shielded
balance.

To create a payment address from your spending key, use:

```shell
namadaw masp gen-payment-addr --spending-key [your spending key]
```

This will generate a different payment address each time you run it.
Payment addresses can be reused or discarded as you like, and can't be
correlated with one another.

Once you have a payment address, transfer a balance from your
transparent account to your shielded spending key with something like:

```shell
namadac transfer --source my-established --payment-address [your payment address] --token btc --amount 100
```

Once this transfer goes through, you can view your spending key's
balance:

```shell
namadac balance --spending-key [your spending key]
```

However, your spending key is the secret key to all your shielded
balances, and you may not want to use it just to view balances. For this
purpose, you can derive the viewing key:

```shell
namadaw masp derive-view-key --spending-key [your spending key]
namadac balance --viewing-key [your viewing key]
```

The viewing key can also be used to generate payment addresses, with
e.g. `namadaw masp gen-payment-addr --viewing-key [your viewing key]`.

Now that you have a shielded balance, it can either be transferred to a
different shielded payment address (shielded to shielded):

```shell
namadac transfer --spending-key [your spending key] --payment-address [someone's payment address] --token btc --amount 50 --signer my-established
```

or to a transparent account (shielded to transparent):

```shell
namadac transfer --spending-key [your spending key] --target [some transparent account] --token btc --amount 50 --signer my-established
```

Note that for both of these types of transfer, `--signer` must be
specified. However, any transparent account can sign these transactions.

## Troubleshooting

### Build from Source

Build the provided validity predicate, transaction and matchmaker wasm modules

```shell
make build-wasm-scripts-docker
```

### Node is not starting

**"No state could be found"**

If you get the following log, it means that Tendermint is not installed properly on your machine or not available on path. To solve this issue, install Tendermint by following the [Install User Guide](../user-guide/install.md).

```shell
2022-03-30T07:21:09.212187Z  INFO namada_apps::cli::context: Chain ID: anoma-masp-0.3.51d2f83a8412b95
2022-03-30T07:21:09.213968Z  INFO namada_apps::node::ledger: Available logical cores: 8
2022-03-30T07:21:09.213989Z  INFO namada_apps::node::ledger: Using 4 threads for Rayon.
2022-03-30T07:21:09.213994Z  INFO namada_apps::node::ledger: Using 4 threads for Tokio.
2022-03-30T07:21:09.217867Z  INFO namada_apps::node::ledger: VP WASM compilation cache size not configured, using 1/6 of available memory.
2022-03-30T07:21:09.218908Z  INFO namada_apps::node::ledger: Available memory: 15.18 GiB
2022-03-30T07:21:09.218934Z  INFO namada_apps::node::ledger: VP WASM compilation cache size: 2.53 GiB
2022-03-30T07:21:09.218943Z  INFO namada_apps::node::ledger: Tx WASM compilation cache size not configured, using 1/6 of available memory.
2022-03-30T07:21:09.218947Z  INFO namada_apps::node::ledger: Tx WASM compilation cache size: 2.53 GiB
2022-03-30T07:21:09.218954Z  INFO namada_apps::node::ledger: Block cache size not configured, using 1/3 of available memory.
2022-03-30T07:21:09.218959Z  INFO namada_apps::node::ledger: RocksDB block cache size: 5.06 GiB
2022-03-30T07:21:09.218996Z  INFO namada_apps::node::ledger::storage::rocksdb: Using 2 compactions threads for RocksDB.
2022-03-30T07:21:09.219196Z  INFO namada_apps::node::ledger: Tendermint node is no longer running.
2022-03-30T07:21:09.232544Z  INFO namada::ledger::storage: No state could be found
2022-03-30T07:21:09.232709Z  INFO namada_apps::node::ledger: Tendermint has exited, shutting down...
2022-03-30T07:21:09.232794Z  INFO namada_apps::node::ledger: Anoma ledger node started.
2022-03-30T07:21:09.232849Z  INFO namada_apps::node::ledger: Anoma ledger node has shut down.
```
