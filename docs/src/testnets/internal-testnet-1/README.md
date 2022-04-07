# Internal Testnet 1

##### Last updated on 04/07/2022 by Alexandre Roque

>⚠️ the values below might change frequently.
>
>Latest values regarding the testnet that would be useful to have in your shell:
>
>```bash
>export ANOMA_TESTNET_CHAIN_ID='anoma-masp-0.3.51d2f83a8412b95'
>export ANOMA_TESTNET_BRANCH='internal/testnet-n1'
>export ANOMA_TESTNET_COMMIT='0184e64e044366ec370d1431ddf4691b4bd3a5b4'
>```

## Hardware Requirements

This section covers the minimum and recommended hardware requirements for engaging with the Namada as a validator node.

### Minimal Hardware Requirements

| Hardware | Minimal Specifications |
| -------- | -------- |
| CPU     | x86_64 (Intel, AMD) processor with at least 4 physical cores     |
| RAM     | 16GB DDR4     |
| Storage     | at least 60GB SSD (NVMe SSD is recommended. HDD will be enough for localnet only)    |

## Installing Namada
<!-- TODO: refactor this section into User Guide > Installing Namada, then link it here -->

### From Source

If you'd like to install Namada from source you will have to install some dependencies first: [Rust](https://www.rust-lang.org/tools/install), [Git](https://git-scm.com/book/en/v2/Getting-Started-Installing-Git), Clang, OpenSSL and LLVM.

First install Rust.
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```
At the end of the installation, make sure that Cargo's bin directory ($HOME/.cargo/bin) is available on your PATH environment variable. You can either restart your shell or run `source $HOME/.cargo/env` to continue.

If you already have Rust installed, make sure you're using the latest version by running:
```bash
rustup update
```
Then, install the remaining dependencies.

**Ubuntu:** running the following command should install everything needed:
```bash
sudo apt-get install -y make git-core libssl-dev pkg-config libclang-12-dev
```
**Mac:** installing the Xcode command line tools should provide you with almost everything you need:
```bash
xcode-select --install
```
Now, that you have all dependencies installed you can clone the source code from the [Anoma repository](https://github.com/anoma/anoma) and build it with:

```bash
git clone https://github.com/anoma/anoma.git --single-branch --branch $ANOMA_TESTNET_BRANCH
cd anoma 
make install
```

Once done, you can go to [Setting up Namada](#setting-up-namada) section.

### From Binaries

>⚠️ During internal and private testnets, links to releases provided in this section might be outdated and inconsistent to the current testnet.
>To avoid any issues, we recommend you [build from source](#build-from-source).

If you'd like to install Namada from binaries you will have to install some dependencies first: [Rust](https://www.rust-lang.org/tools/install), [Git](https://git-scm.com/book/en/v2/Getting-Started-Installing-Git), [Tendermint](https://docs.tendermint.com/master/introduction/install.html) `0.34.x` and GLIBC `v2.29` or higher.

First install Rust.
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```
At the end of the installation, make sure that Cargo's bin directory ($HOME/.cargo/bin) is available on your PATH environment variable. You can either restart your shell or run `source $HOME/.cargo/env` to continue.

If you already have Rust installed, make sure you're using the latest version by running:
```bash
rustup update
```

Then, install Git. 

**Ubuntu:** running the following command should install Git:
```bash
sudo apt-get install git
```
**Mac:** installing the Xcode command line tools should provide you with almost everything you need:
```bash
xcode-select --install
```
Next, let's install Tendermint. 

You can either follow the instructions on the [Tendermint guide](https://docs.tendermint.com/master/introduction/install.html) or download the `get_tendermint.sh` script from the [Anoma repository](https://github.com/anoma/anoma/blob/master/scripts/install/get_tendermint.sh) and execute it:
```bash
curl -LO https://raw.githubusercontent.com/anoma/anoma/master/scripts/install/get_tendermint.sh
./get_tendermint.sh
```
Now, that you have all dependencies installed you can download the latest binary `v0.5.0` from our [releases](https://github.com/anoma/anoma/releases) page by replacing `{platform}` by either `Linux-x86_64` or `Darwin-x86_64` for Mac:
```bash
curl -LO https://github.com/anoma/anoma/releases/download/v0.5.0/anoma-v0.5.0-{platform}.tar.gz
tar -xzf anoma-v0.5.0-{platform}.tar.gz && cd anoma-v0.5.0-{platform}
```
Finally, you should have GLIBC `v2.29` or higher.

On recent versions of **macOS**, the system-provided glibc should be recent enough

On **Ubuntu 20.04**, this is installed by default and you don't have to do anything more. 

On **Ubuntu 18.04**, glibc has `v2.27` by default which is lower than the required version to run Namada. We recommend to directly [install from source](#from-source) or upgrade to Ubuntu 19.04, instead of updating glibc to the required version, since the latter way can be a messy and tedious task. In case, updating glibc would interest you this [website](http://www.linuxfromscratch.org/lfs/view/9.0-systemd/chapter05/glibc.html) gives you the steps to build the package from source.

You are now ready to set up your Namada node.

## Setting up Namada

At this point, depending on your installation choice, we will assume that you are either in `anoma` or `anoma-v0.5.0-{platform}` folder.

### Join a network

To join the current testnet, you need to download the configuration files. This can be done easily with:

```bash
anomac utils join-network --chain-id $ANOMA_TESTNET_CHAIN_ID
```

It should output something like this where the chain id might differ:

```
Downloading config release from https://github.com/heliaxdev/anoma-network-config/releases/download/anoma-masp-0.3.51d2f83a8412b95/anoma-masp-0.3.51d2f83a8412b95.tar.gz ...
Successfully configured for chain ID anoma-masp-0.3.51d2f83a8412b9`
```

The above command downloads the folder `.anoma` which contains a global config file `global-config.toml`; the genesis file for the specified chain id `{chain-id}.toml` and its corresponding configuration folder `{chain-id}` which contains the checksums for the wasm files under `wasm` and the p2p config `config.toml`. 

### Setup the MASP parameters

Namada uses a multi-asset shielded pool (MASP) to enable private transfers. The pool relies on three circuits which require each individually their randomly generated parameters to work.

>⚠️ Normally, the parameters are downloaded through the `masp` crate by the client, but in case of troubles you should get them from someone in the team and follow the instructions below.

<!-- You can download the parameters with:
```bash
[command]
``` -->

The parameters need to be extracted to the correct folder where the node will read the parameters from. 

**Ubuntu**
```bash
mkdir ~/.masp-params
tar -xvf masp-params.tar.gz ~/.masp-params
```
**Mac**
```bash
mkdir ~/Library/Application\ Support/MASPParams/
tar -xvf masp-params.tar.gz ~/Library/Application\ Support/MASPParams/
```
### Start a node

At this point, you are ready to start your Namada node with:
```bash
anoma ledger
```

To keep your node running after closing your terminal you can use terminal multiplexer like `tmux`. 

## Using Namada

### Shielded transfers

Shielded balances are owned by a particular spending key. In this
testnet, spending keys are just arbitrary hexadecimal strings, provided
on the command line.

To try out shielded transfers, you will first need an ordinary
transparent account with some token balance. Example commands for that:

```
anomaw address gen --alias my-implicit
anomac init-account --source my-implicit --public-key my-implicit --alias my-established
anomac transfer --token btc --amount 1000 --source faucet --target my-established --signer my-established
```

The testnet tokens which the faucet can provide you are named `XAN`,
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

Shielded transfers work with the `anomac transfer` command, but either
`--source`, `--target`, or both are replaced. `--source` may be replaced
with `--spending-key` to spend a shielded balance, but if you are
following along, you don't have a shielded balance to spend yet.
`--target` may be replaced with `--payment-address` to create a shielded
balance.

To create a payment address from your spending key, use:

```
anomaw masp gen-payment-addr --spending-key [your spending key]
```

This will generate a different payment address each time you run it.
Payment addresses can be reused or discarded as you like, and can't be
correlated with one another.

Once you have a payment address, transfer a balance from your
transparent account to your shielded spending key with something like:

```
anomac transfer --source my-established --payment-address [your payment address] --token btc --amount 100
```

Once this transfer goes through, you can view your spending key's
balance:

```
anomac balance --spending-key [your spending key]
```

However, your spending key is the secret key to all your shielded
balances, and you may not want to use it just to view balances. For this
purpose, you can derive the viewing key:

```
anomaw masp derive-view-key --spending-key [your spending key]
anomac balance --viewing-key [your viewing key]
```

The viewing key can also be used to generate payment addresses, with
e.g. `anomaw masp gen-payment-addr --viewing-key [your viewing key]`.

Now that you have a shielded balance, it can either be transferred to a
different shielded payment address (shielded to shielded):

```
anomac transfer --spending-key [your spending key] --payment-address [someone's payment address] --token btc --amount 50 --signer my-established
```

or to a transparent account (shielded to transparent):

```bash
anomac transfer --spending-key [your spending key] --target [some transparent account] --token btc --amount 50 --signer my-established
```

Note that for both of these types of transfer, `--signer` must be
specified. However, any transparent account can sign these transactions.

### Troubleshooting

#### Build from Source

This is required to build the wasm validity predicates.

```
rustup target add wasm32-unknown-unknown
```

Build the provided validity predicate, transaction and matchmaker wasm modules

```
make build-wasm-scripts-docker
```

#### Node is not starting

**No state could be found**
If you get the following log, it means that tendermint is not installed properly on your machine. To solve this issue follow the [prerequisites](#prerequisites).

```bash
2022-03-30T07:21:09.212187Z  INFO anoma_apps::cli::context: Chain ID: anoma-masp-0.3.51d2f83a8412b95
2022-03-30T07:21:09.213968Z  INFO anoma_apps::node::ledger: Available logical cores: 8
2022-03-30T07:21:09.213989Z  INFO anoma_apps::node::ledger: Using 4 threads for Rayon.
2022-03-30T07:21:09.213994Z  INFO anoma_apps::node::ledger: Using 4 threads for Tokio.
2022-03-30T07:21:09.217867Z  INFO anoma_apps::node::ledger: VP WASM compilation cache size not configured, using 1/6 of available memory.
2022-03-30T07:21:09.218908Z  INFO anoma_apps::node::ledger: Available memory: 15.18 GiB
2022-03-30T07:21:09.218934Z  INFO anoma_apps::node::ledger: VP WASM compilation cache size: 2.53 GiB
2022-03-30T07:21:09.218943Z  INFO anoma_apps::node::ledger: Tx WASM compilation cache size not configured, using 1/6 of available memory.
2022-03-30T07:21:09.218947Z  INFO anoma_apps::node::ledger: Tx WASM compilation cache size: 2.53 GiB
2022-03-30T07:21:09.218954Z  INFO anoma_apps::node::ledger: Block cache size not configured, using 1/3 of available memory.
2022-03-30T07:21:09.218959Z  INFO anoma_apps::node::ledger: RocksDB block cache size: 5.06 GiB
2022-03-30T07:21:09.218996Z  INFO anoma_apps::node::ledger::storage::rocksdb: Using 2 compactions threads for RocksDB.
2022-03-30T07:21:09.219196Z  INFO anoma_apps::node::ledger: Tendermint node is no longer running.
2022-03-30T07:21:09.232544Z  INFO anoma::ledger::storage: No state could be found
2022-03-30T07:21:09.232709Z  INFO anoma_apps::node::ledger: Tendermint has exited, shutting down...
2022-03-30T07:21:09.232794Z  INFO anoma_apps::node::ledger: Anoma ledger node started.
2022-03-30T07:21:09.232849Z  INFO anoma_apps::node::ledger: Anoma ledger node has shut down.
```
