# 💾 Install Namada

>⚠️ We only support Linux or macOS (at the moment, we are not supporting Windows)

## Hardware Requirements

This section covers the minimum and recommended hardware requirements for engaging with the Namada as a validator node.

### Minimal Hardware Requirements

| Hardware | Minimal Specifications |
| -------- | -------- |
| CPU     | x86_64 or arm64 processor with at least 4 physical cores     |
| RAM     | 16GB DDR4     |
| Storage     | at least 60GB SSD (NVMe SSD is recommended. HDD will be enough for localnet only)    |

There are different ways to install Namada: [From Source](#from-source), [From Binaries](#from-binaries), [From Docker](#from-docker) and [From Nix](#from-nix).

### From Source

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

Now, that you have all dependencies installed you can clone the source code from the [Anoma repository](https://github.com/anoma/anoma) and build it with:

>⚠️ During internal and private testnets, checkout the latest testnet branch using `$ANOMA_TESTNET_BRANCH`.

```shell
git clone https://github.com/anoma/anoma.git
cd anoma 
make install
```

### From Binaries

>⚠️ During internal and private testnets, prebuilt binaries might not be available under our [Github releases page](https://github.com/anoma/anoma/releases).
>We recommend you [build from source](#from-source) from the appropriate branch or commit.

If you'd like to install Namada from binaries you will have to install some dependencies first: [Tendermint](https://docs.tendermint.com/master/introduction/install.html) `0.34.x` and GLIBC `v2.29` or higher.

Let's install Tendermint.

You can either follow the instructions on the [Tendermint guide](https://docs.tendermint.com/master/introduction/install.html) or download the `get_tendermint.sh` script from the [Anoma repository](https://github.com/anoma/anoma/blob/master/scripts/install/get_tendermint.sh) and execute it (will ask you for `root` access):

```shell
curl -LO https://raw.githubusercontent.com/anoma/anoma/master/scripts/install/get_tendermint.sh
chmod +x get_tendermint.sh
./get_tendermint.sh
```

Finally, you should have GLIBC `v2.29` or higher.

**MacOS**: the system-provided glibc should be recent enough.

**Ubuntu 20.04**: this is installed by default and you don't have to do anything more.

**Ubuntu 18.04**: glibc has `v2.27` by default which is lower than the required version to run Namada. We recommend to directly [install from source](#from-source) or upgrade to Ubuntu 19.04, instead of updating glibc to the required version, since the latter way can be a messy and tedious task. In case, updating glibc would interest you this [website](http://www.linuxfromscratch.org/lfs/view/9.0-systemd/chapter05/glibc.html) gives you the steps to build the package from source.

Now, that you have all dependencies installed you can download the latest binary release from our [releases page](https://github.com/anoma/anoma/releases) by choosing the appropriate architecture.

>⚠️ Prebuilt binaries might not be available for a specific release or architecture, in this case you have to [build from source](#from-source).

## From Docker

Go to [heliaxdev dockerhub account](https://hub.docker.com/r/heliaxdev/anoma) and pull the image.

## From Nix

If you have [Nix](https://nixos.org/), you can get Anoma easily as a flake. For
this to work, make sure that you have Nix 2.4 or later and that you have
`experimental-features = nix-command flakes` in your `~/.config/nix/nix.conf`.

```shell
# Install to user profile
nix profile install github:anoma/anoma/<revision>

# Run without installing
nix run github:anoma/anoma/<revision> -- --help

# Enter a shell where anoma executables are available
nix run github:anoma/anoma/<revision>
```

Set `<revision>` to the git tag, branch or hash you want.

With Nix versions older than 2.4, use this command instead:

```shell
nix-env -f https://github.com/anoma/anoma/archive/<revision>.tar.gz -iA default
```
