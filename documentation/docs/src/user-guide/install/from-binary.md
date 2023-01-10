## From Binaries

```admonish warning
Prebuilt binaries might not be available for a specific release or architecture, in this case you have to [build from source](https://docs.namada.net/user-guide/install/from-source.html).
```

If you'd like to install Namada from binaries you will have to install some dependencies first: [Tendermint](https://docs.tendermint.com/master/introduction/install.html) `0.34.x` and GLIBC `v2.29` or higher.

Let's install Tendermint.

You can either follow the instructions on the [Tendermint guide](https://docs.tendermint.com/master/introduction/install.html) or download the `get_tendermint.sh` script from the [Namada repository](https://raw.githubusercontent.com/anoma/namada/main/scripts/get_tendermint.sh) and execute it (will ask you for `root` access):

```shell
curl -LO https://raw.githubusercontent.com/anoma/namada/main/scripts/get_tendermint.sh
chmod +x get_tendermint.sh
./get_tendermint.sh
```

Finally, you should have GLIBC `v2.29` or higher.

**MacOS**: the system-provided glibc should be recent enough.

**Ubuntu 20.04**: this is installed by default and you don't have to do anything more.

**Ubuntu 18.04**: glibc has `v2.27` by default which is lower than the required version to run Namada. We recommend to directly [install from source](#from-source) or upgrade to Ubuntu 19.04, instead of updating glibc to the required version, since the latter way can be a messy and tedious task. In case, updating glibc would interest you this [website](http://www.linuxfromscratch.org/lfs/view/9.0-systemd/chapter05/glibc.html) gives you the steps to build the package from source.

Now, that you have all dependencies installed you can download the latest binary release from our [releases page](https://github.com/anoma/namada/releases) by choosing the appropriate architecture.