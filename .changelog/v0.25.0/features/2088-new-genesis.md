- Added bech32m string encoding for `common::PublicKey` and `DkgPublicKey`.
  ([\#2088](https://github.com/anoma/namada/pull/2088))
- Added `--pre-genesis` argument to the wallet commands to allow to generate
  keys, implicit addresses and shielded keys without having a chain setup. If
  no chain is setup yet (i.e. there's no base-dir or it's empty), the wallet
  defaults to use the pre-genesis wallet even without the `--pre-genesis`
  flag. The pre-genesis wallet is located inside base-dir in
  `pre-genesis/wallet.toml`.
  ([\#2088](https://github.com/anoma/namada/pull/2088))
- Reworked the genesis templates, setup and related utils commands.
  ([\#2088](https://github.com/anoma/namada/pull/2088))
