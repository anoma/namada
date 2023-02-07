- Refactored PoS storage using lazy data collections, that allow to implement
  PoS state changes for collections with variable size with a bounded gas cost.
  ([#16](https://github.com/anoma/namada/issues/16))
- The unbonding action has been updated to affect validator voting power at
  `pipeline` offset and become withdrawable starting from `pipeline + unbonding`
  offset. ([#366](https://github.com/anoma/namada/issues/366))
- The PoS `client bonds` query has been improved to show all delegations to a
  validator, when only the `--validator` argument is specified.
  ([#43](https://github.com/anoma/namada/issues/43))
- Removed PoS validator `Pending` state.
  ([#157](https://github.com/anoma/namada/issues/157))
- Renamed PoS `active` and `inactive` validator sub-sets to `consensus` and
  `below_capacity` sets.
  ([#787](https://github.com/anoma/namada/issues/787))
- Renamed PoS variables that look-up a sum of delta values from `total_deltas`
  to `total_stake`.  ([#158](https://github.com/anoma/namada/issues/158))
- Added PoS validator sets tests.
  ([#15](https://github.com/anoma/namada/issues/15))
- Added PoS genesis initialization tests.
  ([#13](https://github.com/anoma/namada/issues/13))
