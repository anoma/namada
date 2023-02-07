- Improved the `WlStorage` to write protocol changes via block-level write log.
  This is then used to make sure that no storage changes are committed in ABCI
  `FinalizeBlock` request handler and only in the `Commit` handler.
  ([#1108](https://github.com/anoma/namada/pull/1108))
