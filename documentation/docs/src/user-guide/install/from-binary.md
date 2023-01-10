## From Binaries

```admonish warning
Prebuilt binaries might not be available for a specific release or architecture, in this case you have to [build from source](#from-source).
```

### Installing Tendermint

Start by exporting the variable

```bash
export TM_HASH=v0.1.4-abciplus
```

Install the heliaxdev/tendermint fork
```bash
git clone https://github.com/heliaxdev/tendermint && cd tendermint && git checkout $TM_HASH
make build
```
The above requires that golang is correctly installed with the correct $PATH setup
- In linux, this can be resolved by
- `sudo snap install go --channel=1.18/stable --classic`
- Copy both the namada and tendermint binaries to somewhere on $PATH (or uselol the relative paths) 
- This step may or may not be necessary
- namada binaries can be found in `/target/release`
- tendermint is in `build/tendermint`


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

### Downloading the binaries

Now, that you have all dependencies installed you can download the latest binary release from our [releases page](https://github.com/anoma/namada/releases) by choosing the appropriate architecture.

### Placing the binaries onto `$PATH`
For ubuntu and mac machines, the following command should work for placing namada into path

Once inside the directory containing the binaries:
```bash
sudo cp ./namada* /usr/local/bin/
```