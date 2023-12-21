- Fixed replay protection to avoid iterators with key that don't match its
  prefix, which was triggering recursive call that was growing stack with every
  new applied tx. Replaced recursion from RocksDB that was growing stack size
  with a loop. ([\#2325](https://github.com/anoma/namada/pull/2325))