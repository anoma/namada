- Modified rechecks of process proposal to actually use `process_proposal`
  instead of `process_txs`. Added a caching mechanism to avoid
  running the check for a given proposed block more than once.
  ([\#3473](https://github.com/anoma/namada/pull/3473))