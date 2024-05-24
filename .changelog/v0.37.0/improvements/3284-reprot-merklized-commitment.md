- Replay protection entries need to be verifiable and thus should contribute to the app hash. This PR makes
  a cryptographic commitment to all replay protection entries (the root of some implicit merkle tree) which is itself
  merklized. ([\#3284](https://github.com/anoma/namada/pull/3284))