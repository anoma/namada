# Internal Testnet 1
*Last updated on **3/30/2022** by **Alexandre Roque***

Current chain id `anoma-masp-0.3.51d2f83a8412b95` and branch `tomas/masp-wasm-build-fixes`
## Run MASP Testnet
**NOTE** Check the [prerequisities](#prerequisites) before trying to start a node from binaries.

- Download `masp-params.tar.gz` and `anoma-v0.5.0-49-g0184e64e0-Linux-x86_64.tar.gz` [from Google Drive](https://drive.google.com/drive/folders/1MM-HOkxDgcbgKbTn8E2xVHVKPhiKBI9C?usp=sharing) 
- Extract masp params file `masp-params.tar.gz` 
    - Linux: into home dir as follow `~/.masp-params`
    - Mac OS: into `~/Library/Application Support/MASPParam`
- Extract anoma file with prebuilt binaries `anoma-v0.5.0-49-g0184e64e0-Linux-x86_64.tar.gz`
- Go to anoma folder `anoma-v0.5.0-49-g0184e64e0-Linux-x86_64`
- Join chain-id `anoma-masp-0.3.51d2f83a8412b95` and start your node 

Executing the commands below should start a node:
```bash
cd ~ 
tar -xvf masp-params.tar.gz
tar -xvf anoma-v0.5.0-49-g0184e64e0-Linux-x86_64.tar.gz
cd anoma-v0.5.0-49-g0184e64e0-Linux-x86_64
./anomac utils join-network --chain-id anoma-masp-0.3.51d2f83a8412b95
./anoma ledger
```

## Try MASP commands
* Transparent to shielded payment: `anomac transfer --source Bertha --amount 50 --token BTC --payment-address 9cb63488b1d6ef25f069b6eb5bba2eee3dcf22bc10b2063a1fbcb91964341d75837bdce3e2fe3ec9c1e005`
* Shielded to transparent payment: `anomac transfer --target Bertha --amount 45 --token BTC --spending-key AA`
* View shielded balance using spending key: `anomac balance --spending-key AA`
* View shielded balance using viewing key: `anomac balance --viewing-key 628a9956322f3f7d20b19801d9b4a8f3cb4b8b756a26ef2477feb5264be7b808c920996f37a79433d08e27fefcda0b6736c296b1073734a4ee35d11368f2b52ef14d7c1749cc8119ecc8a894f696992453f2dd78ef1e9d74172b2a5ef7cc8c50`
* Derive view key from spending key: `anomaw masp derive-view-key --spending-key AA`
* Generate payment address from spending key: `anomaw masp gen-payment-addr --spending-key AA`
* Generate payment address from viewing key: `anomaw masp gen-payment-addr --viewing-key 628a9956322f3f7d20b19801d9b4a8f3cb4b8b756a26ef2477feb5264be7b808c920996f37a79433d08e27fefcda0b6736c296b1073734a4ee35d11368f2b52ef14d7c1749cc8119ecc8a894f696992453f2dd78ef1e9d74172b2a5ef7cc8c50`
* Shielded to shielded payment: `anomac transfer --spending-key AA --amount 5 --token BTC --payment-address 9cb63488b1d6ef25f069b6eb5bba2eee3dcf22bc10b2063a1fbcb91964341d75837bdce3e2fe3ec9c1e005 --signer Albert`

## Hardware Requirements

This section covers the minimum and recommended hardware requirements for engaging with the Namada as a validator node.

### Minimal Hardware Requirements
| Hardware | Minimal Specifications |
| -------- | -------- |
| CPU     | x86_64 (Intel, AMD) processor with at least 4 physical cores     |
| RAM     | 16GB DDR4     |
| Storage     | at least 60GB SSD (NVMe SSD is recommended. HDD will be enough for localnet only)    |

## Run a Node from Prebuilt Binaries
This is a quickstart guide to install and run Anoma. If you want to install Anoma from Source, Docker or Nix check section [Install Anoma](https://docs.anoma.network/v0.5.0/user-guide/install.html) and then come back to this section to run your node.

### Install Anoma 
#### From Prebuilt Binaries
##### Prerequisites
- [Rust](https://www.rust-lang.org/tools/install)
- [Git](https://git-scm.com/book/en/v2/Getting-Started-Installing-Git)
- Tendermint 0.34.x pre-installed:
    - [Download any of the pre-built binaries for versions 0.34.x](https://github.com/tendermint/tendermint/releases) and install it using the instructions on the [Tendermint guide](https://docs.tendermint.com/master/introduction/install.html)
    - or use the script from the Anoma repo [`scripts/install/get_tendermint.sh`](https://github.com/anoma/anoma/blob/master/scripts/install/get_tendermint.sh). This is used by the make install command (if you’re installing from the source).
- GLIBC v2.29 or higher
    - On Ubuntu, you can check your glibc version with `ldd --version`
    - By default, the highest version of GLIBC for Ubuntu 18.04 should be 2.27. The best way to go for Ubuntu 18.04 is to build from source, but if you still want to upgrade to a higher version then follow one of the following points:
        - The second option is to migrate your application to a system that supports GLIBC higher than or equal to 2.29. This would mean a lot of work though. It seems Ubuntu 19.04 actually uses that version.
        - The thired option would be to actually build your GLIBC from source using the version you want or need. I’ve researched it a bit and found a website which actually gives you the steps for you to build the package from source : http://www.linuxfromscratch.org/lfs/view/9.0-systemd/chapter05/glibc.html

###### Optional prerequisites
- [Tmux](https://github.com/tmux/tmux/wiki/Installing) Terminal Multiplexer (to keep the node running in the background)

*Note: we don't support Windows at this point in time.*
- Open your favorite Terminal
- Install the [Anoma release v0.3.1](https://github.com/anoma/anoma/releases/tag/v0.3.1) on your machine by running:

**Linux**
```bash
curl -LO https://github.com/anoma/anoma/releases/download/v0.3.1/anoma-v0.3.1-Linux-x86_64.tar.gz
tar -xzf anoma-v0.3.1-Linux-x86_64.tar.gz
cd anoma-v0.3.1-Linux-x86_64
```
**MacOS**
```bash
curl -LO https://github.com/anoma/anoma/releases/download/v0.3.1/anoma-v0.3.1-Darwin-x86_64.tar.gz
tar -xzf anoma-v0.3.1-Darwin-x86_64.tar.gz
cd anoma-v0.3.1-Darwin-x86_64
```

#### From Source
##### Prerequisites
To build from source you will have to install some dependencies:
- [Rust](https://www.rust-lang.org/tools/install)
- [Git](https://git-scm.com/book/en/v2/Getting-Started-Installing-Git)
- Clang
- OpenSSL
- LLVM

For ubuntu users, the following command should install everything necessary:
```
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
sudo apt-get install -y make git-core libssl-dev pkg-config libclang-12-dev
```
Clone the source code from the [Github Anoma repo](https://github.com/anoma/anoma), then build and install anoma with the following commands:

```
git clone https://github.com/anoma/anoma.git
cd anoma
make install
```

### Run Anoma
- Configure your node to join a network:
```
./anomac utils join-network --chain-id=anoma-masp-0.1.52ff4afab144c26
```

This should output the following:
```
Downloading config release from https://github.com/heliaxdev/anoma-network-config/releases/download/anoma-masp-0.1.52ff4afab144c26/anoma-masp-0.1.52ff4afab144c26.tar.gz ...
Successfully configured for chain ID anoma-masp-0.1.52ff4afab144c26
```
- Run the ledger into a tmux session:
```
tmux new -s anoma
./anoma ledger
```
Detach from the anoma tmux session by pressing `Ctrl-B then D`.
Attach again to your anoma tmux session by running:
```
tmux a -t anoma
```

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
