# Getting started

This guide assumes that the Anoma binaries are [installed](./install.md) and available on path. These are:

- `anoma`: The main binary that can be used to interact with all the components of Anoma
- `anoman`: The ledger and intent gossiper node
- `anomac`: The client
- `anomaw`: The wallet

The main binary `anoma` has sub-commands for all of the other binaries:

- `anoma client = anomac`
- `anoma node   = anoman`
- `anoma wallet = anomaw`

To explore the command-line interface, add `--help` argument at any sub-command level to find out any possible sub-commands and/or arguments.

## Joining a testnet

Before most commands will work, you will need to join a testnet with the `anoma client utils join-network` command and the chain ID of a live network. See the [testnets](../testnets) section for details of how to do this.
