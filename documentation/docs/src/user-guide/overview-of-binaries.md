# Overview of binaries

This guide assumes that the Namada binaries are [installed](./install.md) and available on path. These are:

- `namada`: The main binary that can be used to interact with all the components of Namada
- `namadan`: The ledger node
- `namadac`: The client
- `namadaw`: The wallet

The main binary `namada` has sub-commands for all of the other binaries:

- `namada client = namadac`
- `namada node   = namadan`
- `namada wallet = namadaw`

To explore the command-line interface, add `--help` argument at any sub-command level to find out any possible sub-commands and/or arguments.

```admonish tip title="Adding binaries to path" collapsible=true
The binaries should be added to `$PATH` from the `make install` command. However, if this for some reason did not work, a solution may be to copy the binaries from `namada/target/release` to `home/$USER/.local/bin/` for example:

`sudo cp namada/target/release/namada* /home/alice/.local/bin/`
```