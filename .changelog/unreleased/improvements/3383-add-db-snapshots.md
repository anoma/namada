* Resolves the first two points of Issue [\#3307](https://github.com/anoma/namada/issues/3307):
   - Add the ability to create chunkable snapshots to our rocksdb implementation
   - Spawn a background task to create snapshots are certain blockheights

   Specifically adds a config parameter that indicates after how many blocks a 
   snapshot should be created. If set, then on the corresponding calls to commit,
   a background task is spun up that takes a snapshot of rocksDB and writes it
   in a convenient format to a file. This file contains metadata of how to be 
   broken up into chunks. Once a new snapshot is created, older snapshots are
   removed. ([\#3383](https://github.com/anoma/namada/pull/3383))