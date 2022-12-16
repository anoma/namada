# Install Namada

```admonish warning
At the moment, Namada only supports Linux and macOS. 
```

## Hardware Requirements

This section covers the minimum and recommended hardware requirements for engaging with Namada as a validator node.

### Minimal Hardware Requirements

| Hardware | Minimal Specifications |
| -------- | -------- |
| CPU     | x86_64 or arm64 processor with at least 4 physical cores     |
| RAM     | 16GB DDR4     |
| Storage     | at least 60GB SSD (NVMe SSD is recommended. HDD will be enough for localnet only)    |

There are different ways to install Namada:

- [From Source](#from-source)
- [From Binaries](#from-binaries)
- [From Docker](#from-docker)

## From Source

If you'd like to install Namada from source you will have to install some dependencies first: [Rust](https://www.rust-lang.org/tools/install), [Git](https://git-scm.com/book/en/v2/Getting-Started-Installing-Git), Clang, OpenSSL and LLVM.

First, [install Rust](https://www.rust-lang.org/tools/install) by following the instructions from the official page.

At the end of the installation, make sure that Cargo's bin directory ($HOME/.cargo/bin) is available on your PATH environment variable. You can either restart your shell or run `source $HOME/.cargo/env` to continue.

If you already have Rust installed, make sure you're using the latest version by running:

```shell
rustup update
```

Then, install the remaining dependencies.

**Ubuntu:** running the following command should install everything needed:

```shell
sudo apt-get install -y make git-core libssl-dev pkg-config libclang-12-dev build-essential
```

**Mac:** installing the Xcode command line tools should provide you with almost everything you need:

```shell
xcode-select --install
```

Now, that you have all dependencies installed you can clone the source code from the [Namada repository](https://github.com/anoma/namada) and build it with:

```admonish warning
During internal and private testnets, checkout the latest testnet branch using `git checkout $NAMADA_TESTNET_BRANCH`.
```

```shell
git clone https://github.com/anoma/namada.git
cd namada 
make install
```

## From Binaries

```admonish warning
Prebuilt binaries might not be available for a specific release or architecture, in this case you have to [build from source](#from-source).
```

If you'd like to install Namada from binaries you will have to install some dependencies first: [Tendermint](https://docs.tendermint.com/master/introduction/install.html) `0.34.x` and GLIBC `v2.29` or higher.

Let's install Tendermint.

You can either follow the instructions on the [Tendermint guide](https://docs.tendermint.com/master/introduction/install.html) or download the `get_tendermint.sh` script from the [Namada repository](https://github.com/anoma/namada/blob/master/scripts/install/get_tendermint.sh) and execute it (will ask you for `root` access):

```shell
curl -LO https://raw.githubusercontent.com/namada/namada/main/scripts/install/get_tendermint.sh
chmod +x get_tendermint.sh
./get_tendermint.sh
```

Finally, you should have GLIBC `v2.29` or higher.

**MacOS**: the system-provided glibc should be recent enough.

**Ubuntu 20.04**: this is installed by default and you don't have to do anything more.

**Ubuntu 18.04**: glibc has `v2.27` by default which is lower than the required version to run Namada. We recommend to directly [install from source](#from-source) or upgrade to Ubuntu 19.04, instead of updating glibc to the required version, since the latter way can be a messy and tedious task. In case, updating glibc would interest you this [website](http://www.linuxfromscratch.org/lfs/view/9.0-systemd/chapter05/glibc.html) gives you the steps to build the package from source.

Now, that you have all dependencies installed you can download the latest binary release from our [releases page](https://github.com/anoma/namada/releases) by choosing the appropriate architecture.

[fixme]: <> (update docker config as soon as Namada is transferred fully to Namada)

## From Docker

The docker image can be found [here](https://github.com/anoma/namada/pkgs/container/namada)
