- Removed associated type on `masp::ShieldedUtils`. This type was an
  attempt to reduce the number of generic parameters needed when interacting
  with MASP but resulted in making code re-use extremely difficult.
  ([\#1670](https://github.com/anoma/namada/pull/1670))