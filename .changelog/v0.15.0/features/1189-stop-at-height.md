- Introduced a new ledger sub-command: `run-until`. Then, at the provided block
  height, the node will either halt or suspend. If the chain is suspended, only
  the consensus connection is suspended. This means that the node can still be
  queried. This is useful for debugging purposes.
  ([#1189](https://github.com/anoma/namada/pull/1189))
