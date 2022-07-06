# Web Wallet

## IBC Protocol

The web wallet must be able to interact with other chains via the Inter-Blockchain Communication Protocol (IBC).

We need to be able to support the following:

- Inter-chain accounts (ICS027)
- Fungible token transfer (ICS020) from Namada to other Anoma chains
- Fungible token transfer (ICS020) from Namada to Cosmos

What the UI will need to display to the user:

- Select a chain (chain ID) as destination
- Specify a destination address (input)
- Specify a token type
- Specify an amount to transfer

_Further documentation TBD_

## Resources

- [Anoma Ledger IBC Rust Docs](https://docs.anoma.network/master/rustdoc/anoma/ledger/ibc/)
- [HackMD IBC Summary](https://hackmd.io/H2yGO3IQRLiWCPWwQQdVow)
- [ibc-rs](https://github.com/informalsystems/ibc-rs/)
- [ICS020 - Fungible Token Transfers](https://github.com/cosmos/ibc/blob/master/spec/app/ics-020-fungible-token-transfer/README.md)
- [ICS027 - Interchain Accounts](https://github.com/cosmos/ibc/tree/master/spec/app/ics-027-interchain-accounts)
- https://spec.anoma.network/master/architecture/namada/ibc.html
- https://docs.cosmos.network/master/ibc/overview.html
- https://ibcprotocol.org/
