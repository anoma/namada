# Namada versioning scheme

Namada versioning scheme follows the Cargo built-in SemVer rules (<https://semver.org>), with an addition of using the `MAJOR` to also denote consensus breaking changes.

We combine `CONSENSUS` version with `MAJOR` version, using a constant `OFFSET = 100`:

> `{CONSENSUS * OFFSET + MAJOR}.{MINOR}.{PATCH}`

This makes it possible to rely on the Cargo built-in logic for auto-updating dependencies (i.e. `CONSENSUS` and `MAJOR` updates are non-compatible, `MINOR` and `PATCH` are compatible and can be updated automatically without additional intervention).

Note that `CONSENSUS` may change without `MAJOR` API changes and, vice-versa, `MAJOR` API change can occur without a change in `CONSENSUS`.

The total order of version strings is preserved. E.g. changes in:

- `CONSENSUS` version: `v101.0.0` < `v201.0.0`
- `MAJOR`: `v101.0.0` < `v102.0.0`
- `MINOR`: `v101.0.0` < `v101.1.0`
- `PATCH`: `v101.0.0` < `v101.0.1`

This versioning scheme applies since version the release of apps v1.1.0 and libs v0.47.0. The `CONSENSUS` version in these versions is considered to be `0`.

Starting from CONSENSUS version `1`, the version number is written in `CONSENSUS_VERSION` file in the root of this repository and made available via `namada_core::consensus_version` (re-exported in `namada_sdk`).

## `CONSENSUS` and `MAJOR` version resetting

In SemVer, when `MAJOR` is bumped, `MINOR` and `PATCH` are reset to `0` and when `MINOR` is bumped `PATCH` is reset to `0`. Note that however on `CONSENSUS` changes we DO NOT reset `MAJOR` version to preserve continuity of API evolution - as mentioned earlier a `CONSENSUS` change may not necessitate `MAJOR` API changes. `MINOR` and `PATCH` versions are still reset to `0` on `CONSENSUS` change.

- As an example of `CONSENSUS` change **without** a `MAJOR` API change: `v101.2.3` -> `v201.0.0`
- `CONSENSUS` change **with** a `MAJOR` API change: `v101.2.3` -> `v202.0.0`
- And `MAJOR` API change **without** a `CONSENSUS` change: `v101.2.3` -> `v102.0.0`

## Libs versioning

Currently the libs are versioned separately (unstable v0.x) from apps (stable v1.x). Both use the same `CONSENSUS` version when compatible.

Before we stabilize the libs API (i.e. before libs v1), the versioning is as follows:

> `0.{CONSENSUS * OFFSET + MAJOR}.{MINOR}`

After we stabilize libs API we will bring this up to match apps version.

## Apps versioning

Other types of apps breaking changes may include e.g. changing the config format in non-compatible way, changing the DB format, wallet file format or other changes which may prevent from resuming node with a state written by a previous version. Such changes are considered non-consensus breaking for as long as two nodes with previous version and new version will always agree on blocks execution. Non-reverse compatible changes should increment `MAJOR` version, fully compatible changes are considered `MINOR`.
