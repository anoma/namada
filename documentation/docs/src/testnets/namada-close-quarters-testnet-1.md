# Namada Close Quarters Testnet 1

This testnet introduces the following new features:

- [on-chain governance](../user-guide/ledger/governance.md) - create and vote for proposals both onchain and offchain
- [MASP (multi-asset shielded pool) transfers](../user-guide/ledger/masp.md) - make private transfers of any Namada token

Future testnets will include more features as described in [the Namada spec](https://specs.anoma.net/master/architecture/namada.html), like IBC (inter-blockchain communication protocol), bridging to the Ethereum blockchain and more.

## Chain information

Latest values regarding the testnet that would be useful to have in your shell:

```shell
export NAMADA_CHAIN_ID='namada-cq-2.a6ebeb093671093b21'
export NAMADA_COMMIT='f1afdffd5e43ad4bb448db7bf5bc1e23464350f7'
```

You will need to compile the binaries from source yourself, make sure you have checked out the specific commit `$NAMADA_COMMIT` to build from, then follow [the building from source guide](../user-guide/install.md#from-source).

## Status

- 2022-05-05: The chain has been setup to start today at 12:00 CET.
- 2022-05-02: We are currently preparing to launch the chain. Applications are open for people to be [genesis validators](../user-guide/genesis-validator-apply.md).
