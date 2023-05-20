# Install Namada

```admonish warning
At the moment, Namada only supports Linux and macOS. 
```

## Pre-requisites
There are certain pre-requisites that need to be installed before installing Namada. 

### Installing Tendermint

Follow [these instructions](./installing-tendermint.md) in order to setup Tendermint.

### Installing GLIBC

Finally, you should have GLIBC `v2.29` or higher.

**MacOS**: the system-provided glibc should be recent enough.

**Ubuntu 20.04**: this is installed by default and you don't have to do anything more.

**Ubuntu 18.04**: glibc has `v2.27` by default which is lower than the required version to run Namada. We recommend to directly [install from source](./from-source.md
) or upgrade to Ubuntu 19.04, instead of updating glibc to the required version, since the latter way can be a messy and tedious task. In case updating glibc would interest you this [website](http://www.linuxfromscratch.org/lfs/view/9.0-systemd/chapter05/glibc.html) gives you the steps to build the package from source.

## Installing Namada
Namada can be installed through the following methods:

1. [From source](./from-source.md)
2. [From binaries](./from-binary.md)
3. [From a docker image](./from-docker.md)

The hardware requirements for installing and running a Namada full node can be found [here](./hardware.md)