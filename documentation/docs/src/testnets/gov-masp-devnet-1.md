# MASP + Governance devnet

This devnet contains the following new features:

- [on-chain governance](../user-guide/ledger/governance.md) - create and vote for proposals both onchain and offchain
- [MASP (multi-asset shielded pool) transfers](../user-guide/ledger/masp.md) - make private transfers of any Namada token

## Chain information

Latest values regarding the testnet that would be useful to have in your shell:

```shell
export NAMADA_CHAIN_ID='anoma-gov-masp.3f1b25f2ee35b2e'
export NAMADA_COMMIT='f1afdffd5e43ad4bb448db7bf5bc1e23464350f7'
```

You can install Namada by following the instructions from the [Install User Guide](../user-guide/install.md). Note that the binaries should be built from `$NAMADA_COMMIT` rather than `master` or a release tag like `v0.5.0`.
