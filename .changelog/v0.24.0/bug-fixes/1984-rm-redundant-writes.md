- Avoid redundant storage deletions in lazy collections that would incur
  extra gas cause and appear in transaction result as changed keys even if not
  changed occurred. This may have caused PoS transactions to run out of gas.
  ([\#1984](https://github.com/anoma/namada/pull/1984))