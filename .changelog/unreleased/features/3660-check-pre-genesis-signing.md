- The command `namadan utils test-genesis` now accepts `--check-can-sign`
  multi-arg that can be used with genesis addresses and/or public keys to
  verify that a pre-genesis wallet in the base directory is able to sign
  with the keys associated with the addresses or with the keys themselves.
  ([\#3660](https://github.com/anoma/namada/pull/3660))