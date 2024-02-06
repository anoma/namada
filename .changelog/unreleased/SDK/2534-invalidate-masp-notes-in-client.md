- Reworked the sdk to support the new speculative state of the
  `ShieldedContext`:\n-`ShieldedContext` now has an extra field to determin its
  state\n-When calling `gen_shielded_transfer` the context now invalidates the
  spent notes (if any)\n-The fee unshielding `Transaction` is now built before
  the actual transaction\n-`find_viewing_key` only requires a shared reference
  now ([\#2534](https://github.com/anoma/namada/pull/2534))