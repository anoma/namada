- Added `pre/post` methods into `trait VpEnv` that return objects implementing
  `trait StorageRead` for re-use of library code written on top of `StorageRead`
  inside validity predicates. ([#380](https://github.com/anoma/namada/pull/380))