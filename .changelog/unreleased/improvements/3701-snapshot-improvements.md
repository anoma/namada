- Optimize the format of snapshots taken for state syncing purposes.
  Snapshots are taken over the entire RocksDB database, packaged into
  a `zstd` compressed `tar` archive, and split into 10 MB chunks.
  ([\#3701](https://github.com/anoma/namada/pull/3701))