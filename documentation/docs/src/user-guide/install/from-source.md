# From Source

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