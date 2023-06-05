- Fixed the init-chain handler to stop committing state to the DB
  as it may be re-applied when the node is shut-down before the
  first block is committed, leading to an invalid genesis state.
  ([#1182](https://github.com/anoma/namada/pull/1182))