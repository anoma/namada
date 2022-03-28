# Internal Testnet 1

:::warning
:warning: **Warning:** If you are building from source for masp-devnet, please checkout `0.4-masp` branch with `git checkout 0.4-masp` and then follow the [build from source](#From-Source) section below.

Prebuilt binaries for Mac OS are not available on the release page.
Building from source with Mac M1 processors fails.
:::

## Run MASP Testnet
- [Download folder `week-12-anoma-masp` from Drive, extract it](ttps://drive.google.com/drive/folders/1MM-HOkxDgcbgKbTn8E2xVHVKPhiKBI9C?usp=sharing)
- Extract anoma file with prebuilt binaries `anoma-v0.4.0-126-gf67795fc2-Linux-x86_64.tar.gz`
- Go to anoma folder
- Extract masp params file `masp-params.tar.gz` into anoma folder, outputs `.masp-params` folder
- Extract config file `wasm.masp-testnet.1cdfad5c0d2fb5e63.tar.gz` into anoma folder, outputs `.anoma` config folder
- Remove wasm folder from `.anoma/{chain-id}/wasm/`
- Extract wasm file `wasm.masp-testnet.1cdfad5c0d2fb5e63.tar.gz` into `.anoma/{chain-id}/`

Executing the commands below should start a node:
```bash
tar -xvf anoma-v0.4.0-135-g4856958f2d-Linux-x86_64.tar.gz
cd anoma-v0.4.0-135-g4856958f2d-Linux-x86_64
tar -xvf ../masp-params.tar.gz
tar -xvf ../masp-testnet.1cdfad5c0d2fb5e63.tar.gz
cp ../wasm.masp-testnet.1cdfad5c0d2fb5e63.tar.gz .anoma/masp-testnet.1cdfad5c0d2fb5e63/
cd .anoma/masp-testnet.1cdfad5c0d2fb5e63
rm -r wasm
tar -xvf wasm.masp-testnet.1cdfad5c0d2fb5e63.tar.gz
cd ../../
./anoma ledger
```

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