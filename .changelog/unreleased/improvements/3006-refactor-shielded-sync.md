This PR refactors shielded sync to make the following improvements
    * Allow fetching new masp txs and trial-decrypting notes to happen asynchronously
    * Parallelize the trial-decryptions
    * Modularize the logic so that we can mock parts of the algorithm for tests and to enable migration over to using a specila masp indexer
    * Added test coverage
    * Decouple nullifying notes and updating spent notes from the trial-decryption process
    * Refactor the masp.rs module in the sdk into several smaller files and submodules

[\#3006](https://github.com/anoma/namada/pull/3006)
