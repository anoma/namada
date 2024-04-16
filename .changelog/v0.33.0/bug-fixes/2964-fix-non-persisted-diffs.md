- Replaced DB key-val diffs pruning of non-persisted keys that searched for the
  last diffs and was degrading throughput with a separate DB column family that
  is pruned on every block.
  ([\#2964](https://github.com/anoma/namada/pull/2964))