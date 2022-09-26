# Getting started

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

## Join a network

After you installed Namada, you will need to join a live network (e.g. testnet) to be able to interact with a chain and execute most available commands. You can join a network with the following command:

```
namada client utils join-network --chain-id=<network-chain-id>
```

To join a testnet, head over to the [testnets](../testnets) section for details on how to do this.

## Start your node

As soon as you are connected to a network, you can start your local node with:

```
namada ledger
```

Learn more about the configuration of the Ledger in [The Ledger](./ledger.md) section
