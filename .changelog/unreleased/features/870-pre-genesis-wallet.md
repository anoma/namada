- Added `--pre-genesis` argument to the wallet commands to allow to generate
  keys, implicit addresses and shielded keys without having a chain setup. If
  no chain is setup yet (i.e. there's no base-dir `.namada` or it's empty), the
  wallet defaults to use the pre-genesis wallet even without the `--pre-genesis`
  flag. The pre-genesis wallet is located in `.namada/pre-genesis/wallet.toml`.
  ([#870](https://github.com/anoma/namada/pull/870))
