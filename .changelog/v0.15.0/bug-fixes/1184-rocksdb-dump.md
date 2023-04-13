- Fixed dump-db node utility which was not iterating on db keys correctly
  leading to duplicates in the dump. Added an historic flag to also dump the
  diff keys. ([#1184](https://github.com/anoma/namada/pull/1184))