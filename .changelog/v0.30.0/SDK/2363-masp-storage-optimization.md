- Modified `ShieldedContext` to use `IndexedTx` to track the last indexed
  masp tx. Updated `fetch_shielded_transfer` and `compute_pinned_balance`
  to query the cometBFT rpc endpoints to retrieve masp data.
  Updated `block_search` to accept a fallible cast to `Height`.
  ([\#2363](https://github.com/anoma/namada/pull/2363))