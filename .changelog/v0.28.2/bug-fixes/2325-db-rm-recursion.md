- Fixed DB prefix iterators to avoid iterators with key that don't match the
  given prefix, which was triggering recursive call that was growing stack with
  every new applied tx and on reading state from disk on start-up. Replaced
  recursion from RocksDB that was growing stack size with a loop.
  ([\#2325](https://github.com/anoma/namada/pull/2325))