# CHANGELOG

## v0.18.1

Namada 0.18.1 is a patch release that addresses transaction format changes and minor ledger storage improvements.

### BUG FIXES

- Fixed bug that allowed transactions to be modified without invalidating
  transaction hash ([\#1607](https://github.com/anoma/namada/pull/1607))
- Move the content and code of init proposal transactions
  into separare section to reduce tx size for hardware wallets
  ([\#1611](https://github.com/anoma/namada/pull/1611))

### FEATURES

- Storage: Add a function to delete key-vals matching a given prefix.
  ([\#1632](https://github.com/anoma/namada/pull/1632))

### IMPROVEMENTS

- Separate the transaction building, signing, and submission
  actions in the SDKs API to enable hardware wallet usage
  ([\#1498](https://github.com/anoma/namada/pull/1498))
- Disable encryption when sending transactions
  ([\#1636](https://github.com/anoma/namada/pull/1636))
- Storage: Ensure that prefix iterator only returns key-
  vals in which the prefix key segments are matched fully.
  ([\#1642](https://github.com/anoma/namada/pull/1642))

## v0.18.0

Namada 0.18.0 is a minor release primarily addressing a major change in the token amount representation, the addition of a new validator set category, and other minor improvements to the ledger stability.

### BUG FIXES

- PoS: Ensure that when a validator is slashed, it gets removed from
  validator set in the same epoch in Namada state as in CometBFT's state.
  ([\#1582](https://github.com/anoma/namada/pull/1582))
- Fix signature verification with secp256k1 in WASM VPs.
  ([\#1599](https://github.com/anoma/namada/pull/1599))
- Storage: Fix iterator without a prefix.
  ([\#1615](https://github.com/anoma/namada/pull/1615))

### FEATURES

- Adds a third validator set, the below threshold set, which contains
  all validators whose stake is below some parameterizable threshold.
  ([#1576](https://github.com/anoma/namada/pull/1576))
- Added `NAMADA_LOG_DIR` env var for logging to file(s) and `NAMADA_LOG_ROLLING`
  for setting rolling logs frequency. The rolling frequency can be set to
  never, minutely, hourly or daily. If not set, the default is never.
  ([\#1578](https://github.com/anoma/namada/pull/1578))

### IMPROVEMENTS

- Update clap to the latest version.
  ([\#64](https://github.com/anoma/namada/issues/64))
- Updated wasmer to v2.3.0 and switched from pwasm-utils to wasm-instrument.
  ([\#1604](https://github.com/anoma/namada/pull/1604))

## v0.17.5

Namada 0.17.5 is a maintenance release chiefly addressing MASP
parameter validation.

### IMPROVEMENTS

- Check MASP parameters are correct in the ledger node.
  ([#1619](https://github.com/anoma/namada/pull/1619))

## v0.17.4

Namada 0.17.4 is a minor release improving the codebase by bumping the rust toolchain.

### BUG FIXES

- Fix missing async awaits in MASP load and save calls.
  ([\#1588](https://github.com/anoma/namada/pull/1588))

## v0.17.3

Namada 0.17.3 is a minor release switching from tendermint to cometbft.

### BUG FIXES

- Correctly handle parsing storage key if they are empty.
  ([#1345](https://github.com/anoma/namada/pull/1345))

### FEATURES

- Enable users to change any tendermint config options via namada config.
  ([#1570](https://github.com/anoma/namada/pull/1570))

### IMPROVEMENTS

- Added query endpoint for IBC events replacing Tendermint index.
  ([\#1404](https://github.com/anoma/namada/pull/1404))

### MISCELLANEOUS

- Switch from unreleased Tendermint fork to an official CometBFT release
  v0.37.1. ([\#1476](https://github.com/anoma/namada/pull/1476))

## v0.17.2

Namada 0.17.2 is a minor release featuring improvements to the client stability.

### BUG FIXES

- Do not add address if it already exists in the wallet.
  ([\#1504](https://github.com/anoma/namada/issues/1504))
- When processing slashes, bonds and unbonds that became active after
  the infraction epoch must be properly accounted in order to properly
  deduct stake that accounts for the precise slash amount. A bug
  is fixed in the procedure that properly performs this accounting.
  ([#1520](https://github.com/anoma/namada/pull/1520))
- Fix the message when a client is waiting for a node to sync on queries or
  transactions. ([\#1522](https://github.com/anoma/namada/pull/1522))
- This change will enable usage of the Namada SDK to create MASP transactions
  from non-CLI clients. ([\#1524](https://github.com/anoma/namada/pull/1524))
- Fixing how token balances are displayed in case of missing --token option.
  ([#1528](https://github.com/anoma/namada/pull/1528))
- The slashed token amounts contained inside the bond and unbond information
  returned by the PoS library fn bonds_and_unbonds are fixed and properly
  computed. ([#1533](https://github.com/anoma/namada/pull/1533))
- PoS: Fixed the client to change configuration to validator
  mode after a successful `init-validator` transaction.
  ([\#1549](https://github.com/anoma/namada/pull/1549))
- PoS: fixed a check for whether a given address belongs to a
  validator account to work properly with newly created accounts.
  ([\#1553](https://github.com/anoma/namada/pull/1553))
- Fixes the slash rate output in the query_slashes client
  command and some redundancy in misbehavior reporting logs.
  ([#1558](https://github.com/anoma/namada/pull/1558))

### IMPROVEMENTS

- Add a command, `namadac utils default-base-dir`, to
  print the default base directory the command
  line would use were one not provided by the user.
  ([#1491](https://github.com/anoma/namada/pull/1491))
- Improve the established address in-memory representation
  and use a full SHA-256 digest for their generation.
  ([\#1510](https://github.com/anoma/namada/pull/1510))
- Improve the implicit address and PKH in-memory representation.
  ([\#1512](https://github.com/anoma/namada/pull/1512))
- Improve help message for address add command
  ([\#1514](https://github.com/anoma/namada/issues/1514))
- PoS: make a re-usable bonds and unbonds details query.
  ([\#1518](https://github.com/anoma/namada/pull/1518))

## v0.17.1

Namada 0.17.0 is a scheduled minor release featuring several improvements to the slashing mechanism, 
wallet address derivation, transaction structure and the ledger stability.

### BUG FIXES

- Persists a newly added storage field for epoch update blocks delay to be
  available after node restart when not `None` which may break consensus.
  ([\#1455](https://github.com/anoma/namada/pull/1455))
- Client: Fixed an off-by-one error to stop waiting for start or catch-up when
  max tries are reached. ([\#1456](https://github.com/anoma/namada/pull/1456))
- Include the wasm tx hash instead of the wasm blob when constructing a
  transaction ([#1474](https://github.com/anoma/namada/pull/1474))
- Fix a client block query to avoid seeing pre-committed blocks.
  ([\#1534](https://github.com/anoma/namada/pull/1534))

### DOCS

- Adds specs for gas and fee ([#889](https://github.com/anoma/namada/pull/889))

### FEATURES

- The implementation of the cubic slashing system that touches virtually all
  parts of the proof-of-stake system. Slashes tokens are currently kept in the
  PoS address rather than being transferred to the Slash Pool address. This PR
  also includes significant testing infrastructure, highlighted by the PoS state
  machine test with slashing. ([#892](https://github.com/anoma/namada/pull/892))
- Implements HD wallet derivation / recovery from a given mnemonic code
  ([\#1110](https://github.com/anoma/namada/pull/1110))
- PoS: Added a client command `find-validator --tm-address <address>`
  to find validator's Namada address by Tendermint address.
  ([\#1344](https://github.com/anoma/namada/pull/1344))

### IMPROVEMENTS

- Make Namada transactions signable on hardware constrained wallets by making
  them smaller. ([#1093](https://github.com/anoma/namada/pull/1093))
- Added `multicore` feature flag to the namada and namada_core
  crate that can be switched off for JS WASM build.
  Additionally, changed the `trait ShieldedUtils` to be async.
  ([\#1238](https://github.com/anoma/namada/pull/1238))
- Zeroizes memory containing passphrases in wallet.
  ([\#1425](https://github.com/anoma/namada/issues/1425))
- Added some missing cli option for cli wallet
  ([#1432](https://github.com/anoma/namada/pull/1432))
- Improve logging error when submiting an invalid validator commission change tx
  ([#1434](https://github.com/anoma/namada/pull/1434))
- Correct a typo in the error change commission error handling
  ([#1435](https://github.com/anoma/namada/pull/1435))
- Improve the reveal tx naming in cli
  ([#1436](https://github.com/anoma/namada/pull/1436))
- Improve computations readability when calculating inflations
  ([#1444](https://github.com/anoma/namada/pull/1444))
- Remove abci++ dependencies ([#1449](https://github.com/anoma/namada/pull/1449))
- Reorganize the structure of transactions
  ([#1462](https://github.com/anoma/namada/pull/1462))
- Improved log entries related to PoS system.
  ([\#1509](https://github.com/anoma/namada/pull/1509))

## v0.16.0

Namada 0.16.0 is a regular release focused on providing the Namada SDK
to developers.

### DOCS

- Added page table-of-contents via mdbook-pagetoc plugin for the developer
  documentation. ([#1275](https://github.com/anoma/namada/pull/1275))

### IMPROVEMENTS

- Provide Namada SDK (in particular, the `namada`
crate may now be usefully linked into user
applications). ([#925](https://github.com/anoma/namada/pull/925))
- Bump RocksDB crate to 0.21.0 to address compilation errors on certain C++
  toolchains. ([#1366](https://github.com/anoma/namada/pull/1366))

## v0.15.4

Namada 0.15.4 is a maintenance release addressing the invalid creation of blocks due to missing replay protection checks during prepare 
proposal.

### BUG FIXES

- Fixed a bug in `prepare_proposal` causing the creation
  of blocks containing already applied transactions.
  ([#1405](https://github.com/anoma/namada/pull/1405))

### IMPROVEMENTS

- Make Tendermint consensus paramenters configurable via Namada configuration.
  ([#1399](https://github.com/anoma/namada/pull/1399))
- Improved error logs in `process_proposal` and added more info to
  `InternalStats` ([#1407](https://github.com/anoma/namada/pull/1407))

## v0.15.3

Namada 0.15.3 is a maintenance release addressing the creation of
incorrect data directories on Mac and Windows platforms.

### BUG FIXES

- Place the default data directory in the local rather than the roaming profile
  on Windows. ([#1368](https://github.com/anoma/namada/pull/1368))
- Use blank qualifier and organization, and upcased Namada, to
  construct default base directories on Mac and Windows platforms.
  ([#1369](https://github.com/anoma/namada/pull/1369))

## v0.15.2

Namada 0.15.2 is a bugfix release containing various fixes, including
a major improvement to storage usage.

### BUG FIXES

- Fixed an issue with the iterator of LazyMap with a nested LazyVec collection
  that would match non-data keys and fail to decode those with the data decoder.
  ([#1218](https://github.com/anoma/namada/pull/1218))
- PoS: fixed a function for clearing of historical epoched data
  ([\#1325](https://github.com/anoma/namada/pull/1325))

### FEATURES

- Added a utility command to the CLI to compute a tendermint address from a
  namada public key. ([#1152](https://github.com/anoma/namada/pull/1152))

### IMPROVEMENTS

- Changed the default base directory. On linux, the default path will be `$XDG_DATA_HOME/namada`, on OSX it will be `$HOME/Library/Application Support/com.heliax.namada`.
  ([#1138](https://github.com/anoma/namada/pull/1138))
- RocksDB optimization to reduce the storage usage
  ([#1333](https://github.com/anoma/namada/issues/1333))

### MISCELLANEOUS

- Enabled integer overflow checks in release build.
  ([#1295](https://github.com/anoma/namada/pull/1295))

## v0.15.1

Namada 0.15.1 is a patch release addressing issues with high storage
usage due to duplicative storage of wasm code.

### IMPROVEMENTS

- Disable Tendermint tx_index as default
  ([#1278](https://github.com/anoma/namada/issues/1278))
- Remove wasm code from tx ([#1297](https://github.com/anoma/namada/issues/1297))

## v0.15.0

Namada 0.15.0 is a regular minor release featuring various
implementation improvements.

### BUG FIXES

- Fix to read the prev value for batch delete
  ([#1116](https://github.com/anoma/namada/issues/1116))
- Returns an error when getting proof of a non-committed block
  ([#1154](https://github.com/anoma/namada/issues/1154))
- Fixed dump-db node utility which was not iterating on db keys correctly
  leading to duplicates in the dump. Added an historic flag to also dump the
  diff keys. ([#1184](https://github.com/anoma/namada/pull/1184))
- Fixed an issue with lazy collections sub-key validation with the `Address`
  type. This issue was also affecting the iterator of nested `LazyMap`.
  ([#1212](https://github.com/anoma/namada/pull/1212))
- Fixed various features of the CLI output for querying bonds and performing an
  unbond action. ([#1239](https://github.com/anoma/namada/pull/1239))
- PoS: Fixed an issue with slashable evidence processed
  and applied at a new epoch causing a ledger to crash.
  ([#1246](https://github.com/anoma/namada/pull/1246))
- Addresses are now being ordered by their string format (bech32m)
  to ensure that their order is preserved inside raw storage keys.
  ([#1256](https://github.com/anoma/namada/pull/1256))
- Prevent clients from delegating from a validator account to another validator
  account. ([#1263](https://github.com/anoma/namada/pull/1263))

### FEATURES

- Infrastructure for PoS inflation and rewards. Includes inflation
  using the PD controller mechanism and rewards based on validator block voting
  behavior. Rewards are tracked and effectively distributed using the F1 fee
  mechanism. In this PR, rewards are calculated and stored, but they are not
  yet applied to voting powers or considered when unbonding and withdrawing.
  ([#714](https://github.com/anoma/namada/pull/714))
- Implements governance custom proposals
  ([#1056](https://github.com/anoma/namada/pull/1056))
- Adds expiration field to transactions
  ([#1123](https://github.com/anoma/namada/pull/1123))
- Added a rollback command to revert the Namada state to that of the previous
  block. ([#1187](https://github.com/anoma/namada/pull/1187))
- Introduced a new ledger sub-command: `run-until`. Then, at the provided block
  height, the node will either halt or suspend. If the chain is suspended, only
  the consensus connection is suspended. This means that the node can still be
  queried. This is useful for debugging purposes.
  ([#1189](https://github.com/anoma/namada/pull/1189))

### IMPROVEMENTS

- Return early in PosBase::transfer if an attempt is made to transfer zero
  tokens ([#856](https://github.com/anoma/namada/pull/856))
- Adds hash-based replay protection
  ([#1017](https://github.com/anoma/namada/pull/1017))
- Renamed "ledger-address" CLI argument to "node".
  ([#1031](https://github.com/anoma/namada/pull/1031))
- Added a TempWlStorage for storage_api::StorageRead/Write
  in ABCI++ prepare/process proposal handler.
  ([#1051](https://github.com/anoma/namada/pull/1051))
- Added a wallet section for token addresses to replace hard-
  coded values with addresses loaded from genesis configuration.
  ([#1081](https://github.com/anoma/namada/pull/1081))
- Improved the CLI description of the start time node argument.
  ([#1087](https://github.com/anoma/namada/pull/1087))
- Adds chain id field to transactions
  ([#1106](https://github.com/anoma/namada/pull/1106))
-  update help text on namadc utils join-network so that the url
   displays cleanly on a single line, instead of being cut half way
   ([#1109](https://github.com/anoma/namada/pull/1109))
- Check in the client that the ledger node has at least one
  block and is synced before submitting transactions and queries.
  ([#1258](https://github.com/anoma/namada/pull/1258))

### MISCELLANEOUS

- Clean up some code relating to the Ethereum bridge
  ([#796](https://github.com/anoma/namada/pull/796))
- Updated RocksDB to v0.20.1.
  ([#1163](https://github.com/anoma/namada/pull/1163))

### TESTING

- Add utility code for working with test wasms
  ([#893](https://github.com/anoma/namada/pull/893))

## v0.14.3

Namada 0.14.3 is a bugfix release addressing mainly disk usage
inefficiencies.

### BUG FIXES

- Check if validators are valid in pre-genesis setup.
  ([#1140](https://github.com/anoma/namada/pull/1140))
- Now load conversions from storage even for epoch 1.
  ([\#1244](https://github.com/anoma/namada/pull/1244))

### IMPROVEMENTS

- Write Merkle tree stores only when a new epoch
  ([#1113](https://github.com/anoma/namada/issues/1113))
- Prune old Merkle tree stores.
  ([#1237](https://github.com/anoma/namada/pull/1237))

### TESTING

- Fixed run_ledger_load_state_and_reset test in debug build.
  ([#1131](https://github.com/anoma/namada/pull/1131))

## v0.14.2

Namada 0.14.2 is a maintenance release addressing issues with
proof-of-stake validator logic.

### BUG FIXES

- Fixed the PrefixIter order of iteration in the write-
  log to always match the iteration order in the storage.
  ([#1141](https://github.com/anoma/namada/pull/1141))
- Fixed the init-chain handler to stop committing state to the DB
  as it may be re-applied when the node is shut-down before the
  first block is committed, leading to an invalid genesis state.
  ([#1182](https://github.com/anoma/namada/pull/1182))
- Fixed an issue in which a validator's stake and validator sets
  data gets into an invalid state (duplicate records with incorrect
  values) due to a logic error in clearing of historical epoch data.
  ([#1191](https://github.com/anoma/namada/pull/1191))

### FEATURES

- Added a lazy set collection.
  ([#1196](https://github.com/anoma/namada/pull/1196))

### IMPROVEMENTS

- Ensure that PoS validator consensus keys are unique.
  ([#1197](https://github.com/anoma/namada/pull/1197))

## v0.14.1

Namada 0.14.1 is a bugfix release addressing issues with inactive
validator set updates in proof of stake.

### BUG FIXES

- Fix Tendermint validator set update to properly skip validator with no voting
  power. ([#1146](https://github.com/anoma/namada/pull/1146))

## v0.14.0

Namada 0.14.0 is a scheduled minor release with various protocol
stability improvements.

### BUG FIXES

- Add validation for balances with IBC sub prefix
  ([#354](https://github.com/anoma/namada/issues/354))
- Fixed the prefix iterator method to respect modifications in the write log.
  ([#913](https://github.com/anoma/namada/pull/913))

### DOCS

- Update specs for Ethereum bridge and block allocator
  ([#1058](https://github.com/anoma/namada/pull/1058))

### IMPROVEMENTS

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
- Complete checked arithmetic for Amount type
  ([#748](https://github.com/anoma/namada/issues/748))
- Allow to dump a last committed block's state with `namada node dump-db`
  command. ([#1095](https://github.com/anoma/namada/pull/1095))
- Improved the `WlStorage` to write protocol changes via block-level write log.
  This is then used to make sure that no storage changes are committed in ABCI
  `FinalizeBlock` request handler and only in the `Commit` handler.
  ([#1108](https://github.com/anoma/namada/pull/1108))

### MISCELLANEOUS

- Add command line option to dump transactions while signing them.
  ([#1054](https://github.com/anoma/namada/pull/1054))

### TESTING

- Add e2e tests for multitoken transfers
  ([#886](https://github.com/anoma/namada/pull/886))
- Modify tx_write_storage_key test wasm to be able to modify any arbitrary value
  ([#894](https://github.com/anoma/namada/pull/894))
- Avoid lowercase inputs in tests, so they test whether
  lowercasing is properly performed on those inputs.
  ([#1065](https://github.com/anoma/namada/pull/1065))

## v0.13.3

Namada 0.13.3 is a bugfix release addressing issues with voting power
calculation logic.

### BUG FIXES

- Fixed Tendermint validator set update check to
  respect the PoS tm_votes_per_token parameter.
  ([#1083](https://github.com/anoma/namada/pull/1083))

## v0.13.2

Namada 0.13.2 is a bugfix release addressing issues with the 0.13
release series.

### BUG FIXES

- Fixes testnet wrapper fee checks
  ([#1019](https://github.com/anoma/namada/pull/1019))

### CI

- Correctly report e2e test failures in CI.
  ([#1045](https://github.com/anoma/namada/pull/1045))

### IMPROVEMENTS

- Append Namada version number to tendermint moniker.
  ([#1057](https://github.com/anoma/namada/pull/1057))

### TESTING

- Correct the whitelist test in vp_implicit to use case-insensitive whitelist
  hashes. ([#1037](https://github.com/anoma/namada/pull/1037))
- Address failing e2e tests which were not caught earlier.
  ([#1062](https://github.com/anoma/namada/pull/1062))

## v0.13.1

Namada 0.13.1 is a maintenance release fixing an error in the tx and vp
whitelists.

### BUG FIXES

- Handle the tx and vp hash whitelists case-insensitively.
  ([#1018](https://github.com/anoma/namada/pull/1018))

### IMPROVEMENTS

- More information in transaction logging
  ([#1035](https://github.com/anoma/namada/pull/1035))

## v0.13.0

Namada 0.13.0 is a scheduled minor release.

### BUG FIXES

- Fix the commission rate change wasm test, which failed because an arbitrary
  value for a new rate was allowed that could be equal to the previous rate.
  ([#965](https://github.com/anoma/namada/pull/965))

### BUGS

- Removed 'rev_iter_prefix' from storage API as its implementation
  depends on RocksDB and it doesn't work as expected.
  ([#912](https://github.com/anoma/namada/pull/912))

### FEATURES

- Add a --time argument to the node to specify the time the node should start.
  ([#973](https://github.com/anoma/namada/pull/973))
- Reduce the block size for transactions to 5 MiB.
  ([#974](https://github.com/anoma/namada/pull/974))

### IMPROVEMENTS

- Disable 'Send' on async traits that don't need 'Send'
  futures. This allows to use them with 'wasm-bindgen'.
  ([#900](https://github.com/anoma/namada/pull/900))
- Binary search ledger storage keys to match faster.
  ([#903](https://github.com/anoma/namada/pull/903))
- Make queries data structures public for inclusion in rustdoc.
  ([#909](https://github.com/anoma/namada/pull/909))
- Add a macro to derive storage keys from a struct.
  ([#926](https://github.com/anoma/namada/pull/926))
- Added a basic fee implementation for testnet.
  ([#962](https://github.com/anoma/namada/pull/962))
- Hide the explicit lifetime from StorageRead trait.
  ([#966](https://github.com/anoma/namada/pull/966))
- Allow to set the tracing format with NAMADA_LOG_FMT env var to either full
  (default), json or pretty. ([#968](https://github.com/anoma/namada/pull/968))
- Added an optional PoW challenge to the wrapper transactions for testnets,
  to allow to submit transactions without having enough balance to cover
  the minimum transaction fee and to withdraw tokens from a faucet account.
  ([#969](https://github.com/anoma/namada/pull/969))
- Add genesis parameter to control wrapper transaction fees.
  ([#972](https://github.com/anoma/namada/pull/972))
- Add a max_proposal_bytes parameter to the ledger.
  ([#975](https://github.com/anoma/namada/pull/975))

### MISCELLANEOUS

- Update tendermint to v0.1.4-abciplus.
  ([#667](https://github.com/anoma/namada/pull/667))

### TESTING

- Run fewer cases on update_epoch_after_its_duration, for a faster test suite.
  ([#876](https://github.com/anoma/namada/pull/876))
- Use the correct options (--gas-amount, --gas-
  token) in the ledger_txs_and_queries E2E test.
  ([#911](https://github.com/anoma/namada/pull/911))

## v0.12.2

Namada 0.12.2 is a hotfix release, limiting transactions included in a
block by size.

### BUG FIXES

- Limit block space to under Tendermint's limit, and limit transactions included
  in a block by their size. ([#952](https://github.com/anoma/namada/pull/952))

### MISCELLANEOUS

- Don't attempt to include matchmaker DLLs, which no longer exist, in release
  packages. ([#943](https://github.com/anoma/namada/pull/943))
- Include license information in release binary tarballs.
  ([#945](https://github.com/anoma/namada/pull/945))

## v0.12.1

Namada 0.12.1 is a hotfix release, fixing a node crash on malformed
transactions to the MASP.

### BUG FIXES

- Avoid panicking unwrap()s in vp_verify_masp, to prevent crashing the node on
  malformed transactions. ([#942](https://github.com/anoma/namada/pull/942))

## v0.12.0

Namada 0.12.0 is a scheduled minor release.

### CI

- Run `make check-abcipp` in CI ([#824](https://github.com/anoma/namada/pull/824))
- Run Ethereum bridge CI against more branches
  ([#834](https://github.com/anoma/namada/pull/834))

### DOCS

- Adds specs for replay protection
  ([#440](https://github.com/anoma/namada/pull/440))
- Adds specs for multisig accounts
  ([#680](https://github.com/anoma/namada/pull/680))

### IMPROVEMENTS

- Allow sign extension opcodes in WASM
  ([#833](https://github.com/anoma/namada/pull/833))
- Remove the MerkleValue type and just use byte slices for Merkle tree values.
  ([#846](https://github.com/anoma/namada/pull/846))
- Use index-set to reduce serialized size of block results.
  ([#859](https://github.com/anoma/namada/pull/859))

### TESTING

- Allow size zero bonds in PoS for testing.
  ([#813](https://github.com/anoma/namada/pull/813))

## v0.11.0

Namada 0.11.0 is a scheduled minor release.

### BUG FIXES

- Fix building with the `abcipp` feature again
  ([#754](https://github.com/anoma/namada/pull/754))
- Fixed validation of a validator initialization transaction.
  ([#763](https://github.com/anoma/namada/pull/763))

### FEATURES

- Allow to set the native token via genesis configuration.
  ([#582](https://github.com/anoma/namada/pull/582))
- Added a validity predicate for implicit accounts. This is set in
  protocol parameters and may be changed via governance. Additionally,
  added automatic public key reveal in the client that use an implicit
  account that hasn't revealed its PK yet as a source. It's also
  possible to manually submit reveal transaction with  client command
  ([#592](https://github.com/anoma/namada/pull/592))
- PoS: Removed staking reward addresses in preparation of auto-staked rewards
  system. ([#687](https://github.com/anoma/namada/pull/687))
- Allow to set validator's commission rates and a limit on change of commission
  rate per epoch. Commission rate can be changed via a transaction authorized
  by the validator, but the limit is immutable value, set when the validator's
  account is initialized. ([#695](https://github.com/anoma/namada/pull/695))
- Optimize the PoS code to depend only on bonded stake, removing
  the VotingPower(Delta) structs. This mitigates some previous
  information loss in PoS calculations. Instead, the notion of
  voting power is only relevant when communicating with Tendermint.
  ([#707](https://github.com/anoma/namada/pull/707))
- Update the set of parameters in the PoS system according to the
  latest spec and standardizes the use of the rust_decimal crate
  for parameters and calculations that require fractional numbers.
  ([#708](https://github.com/anoma/namada/pull/708))
- Renamed transaction CLI arguments `--fee-amount` and `--fee-token` to `--gas-
  amount` and `--gas-token`. ([#775](https://github.com/anoma/namada/pull/775))

### IMPROVEMENTS

- Refactored token decimal formatting.
  ([#436](https://github.com/anoma/namada/pull/436))
- Added PoS specific queries ([#570](https://github.com/anoma/namada/pull/570))
- Added a custom events store and replaced WebSocket client for
  transaction results with query endpoints to the events store.
  ([#674](https://github.com/anoma/namada/pull/674))
- Refactored governance code to use storage_api.
  ([#719](https://github.com/anoma/namada/pull/719))
- Public parts of shared `namada` crate have been split up into a
  `namada_core` crate. The `namada_proof_of_stake`, `namada_vp_prelude`
  and `namada_tx_prelude` crates now depend on this `namada_core` crate.
  ([#733](https://github.com/anoma/namada/pull/733))
- Sign over the hash of code rather than code in transaction signing.
  ([#807](https://github.com/anoma/namada/pull/807))

### MISCELLANEOUS

- Improve some docstrings relating to block heights
  ([#650](https://github.com/anoma/namada/pull/650))

### TESTING

- Don't fake a wasm VP for internal addresses in tx tests
  ([#694](https://github.com/anoma/namada/pull/694))

## v0.10.1

Namada 0.10.1 is a point release with fixes to shielded transactions.

### BUG FIXES

- Avoid reading from nonexistent storage keys in shielded-to-shielded transfers.
  ([#797](https://github.com/anoma/namada/pull/797))

## v0.10.0

Namada 0.10.0 is a scheduled minor release, focused on IBC and MASP
integrations.

### BUG FIXES

- Fix compatiblity of IBC Acknowledgement message and FungibleTokenData with
  ibc-go ([#261](https://github.com/anoma/namada/pull/261))
- Fix the block header merkle root hash for response to finalizing block.
  ([#298](https://github.com/anoma/namada/pull/298))
- Fix IBC token transfer to comply with ICS20.
  ([#625](https://github.com/anoma/namada/pull/625))
- Fixed storage read from arbitrary height and added an optional config value
  `shell.storage_read_past_height_limit` to limit how far back storage queries
  can read from. ([#706](https://github.com/anoma/namada/pull/706))
- Fix `make debug-wasm-scripts`, which attempted an incorrect rename.
  ([#720](https://github.com/anoma/namada/pull/720))
- require_latest_height should skip requests with height 0
  ([#752](https://github.com/anoma/namada/pull/752))

### FEATURES

- Add client command 'ibc-transfer'.
  ([#626](https://github.com/anoma/namada/pull/626))
- Added MASP client and wallet functionality. Added new command to view transfer
  history. ([#1234](https://github.com/anoma/anoma/pull/1234))

## v0.9.0

Namada 0.9.0 is a scheduled minor release.

### BUG FIXES

- Add back consensus commit timeout configuration set in tendermint
  ([#671](https://github.com/anoma/namada/pull/671))
- Fix info logs to show by default for namadan
  ([#702](https://github.com/anoma/namada/pull/702))

### FEATURES

- Client: Add a command to query the last committed block's hash, height and
  timestamp. ([#658](https://github.com/anoma/namada/issues/658))

### IMPROVEMENTS

- Replace the handcrafted RPC paths with a new `router!` macro RPC queries
  definition that handles dynamic path matching, type-safe handler function
  dispatch and also generates type-safe client methods for the queries.
  ([#553](https://github.com/anoma/namada/pull/553))
- Move all shell RPC endpoints under the /shell path. This is a breaking change
  to RPC consumers. ([#569](https://github.com/anoma/namada/pull/569))

### MISCELLANEOUS

- Renamed native token from XAN to NAM
  ([#632](https://github.com/anoma/namada/pull/632))

## v0.8.1

Namada 0.8.1 is a point release focused on standardizing Tendermint
compatibility.

### IMPROVEMENTS

- Shim ABCI++ methods for tendermint
  ([#510](https://github.com/anoma/namada/pull/510))

## v0.8.0

Namada 0.8.0 is a regular minor release.

### BUG FIXES

- Switch to a alternative sparse merkle tree implementation for IBC sub-tree
  to be able to support proofs compatible with the current version of ICS23
  ([#279](https://github.com/anoma/namada/pull/279))
- Fixed validator raw hash corresponding to validator address in Tendermint
  ([#326](https://github.com/anoma/namada/pull/326))
- Fix the value recorded for epoch start block height.
  ([#384](https://github.com/anoma/namada/issues/384))
- Fix the rustdoc build. ([#419](https://github.com/anoma/namada/issues/419))
- Fix the value recorded for epoch start block height.
  ([#594](https://github.com/anoma/namada/pull/594))
- Make read_wasm return an error instead of exiting in InitChain
  ([#1099](https://github.com/anoma/anoma/pull/1099))
- Fix the `last_epoch` field in the shell to only be updated when the block is
  committed. ([#1249](https://github.com/anoma/anoma/pull/1249))

### FEATURES

- Added multitoken transfer and query for bridges
  ([#132](https://github.com/anoma/namada/issues/132))
- Added lazy vector and map data structures for ledger storage
  ([#503](https://github.com/anoma/namada/pull/503))

### IMPROVEMENTS

- Validate WASM code of validity predicates written by transactions.
  ([#240](https://github.com/anoma/anoma/pull/240))
- Refactored PoS VP logic ([#318](https://github.com/anoma/namada/pull/318))
- Added a StorageRead trait for a common interface for VPs prior and posterior
  state, transactions and direct storage access for protocol and RPC handlers
  ([#324](https://github.com/anoma/namada/pull/324))
- Added a StorageWrite trait for a common interface for transactions and direct
  storage access for protocol ([#331](https://github.com/anoma/namada/pull/331))
- Re-use encoding/decoding storage write/read and handle any errors
  ([#334](https://github.com/anoma/namada/pull/334))
- Added a simpler prefix iterator API that returns `std::iter::Iterator` with
  the storage keys parsed and a variant that also decodes stored values with
  Borsh ([#335](https://github.com/anoma/namada/pull/335))
- Handles the case where a custom `$CARGO_TARGET_DIR` is set during WASM build
  ([#337](https://github.com/anoma/anoma/pull/337))
- Added `pre/post` methods into `trait VpEnv` that return objects implementing
  `trait StorageRead` for re-use of library code written on top of `StorageRead`
  inside validity predicates. ([#380](https://github.com/anoma/namada/pull/380))
- Fix order of prefix iterator to be sorted by storage
  keys and add support for a reverse order prefix iterator.
  ([#409](https://github.com/anoma/namada/issues/409))
- Re-use `storage_api::Error` type that supports wrapping custom error in `VpEnv` and `TxEnv` traits.
  ([#465](https://github.com/anoma/namada/pull/465))
- Fixed governance parameters, tally, tx whitelist and renamed treasury
  ([#467](https://github.com/anoma/namada/issues/467))
- Enable mdbook-admonish for the specs
  ([#518](https://github.com/anoma/namada/issues/518))
- Extend Merkle tree storage to support multiple Merkle trees with a uniform
  interface. ([#547](https://github.com/anoma/namada/pull/547))
- Fix a typo in an error ([#605](https://github.com/anoma/namada/issues/605))
- Added WASM transaction and validity predicate `Ctx` with methods for host
  environment functions to unify the interface of native VPs and WASM VPs under
  `trait VpEnv` ([#1093](https://github.com/anoma/anoma/pull/1093))
- Allows simple retrival of aliases from addresses in the wallet without
  the need for multiple hashmaps. This is the first step to improving the
  UI if one wants to show aliases when fetching addresses from anoma wallet
  ([#1138](https://github.com/anoma/anoma/pull/1138))
- Allow specifying an absolute path for the wasm directory
  ([#1148](https://github.com/anoma/anoma/issues/1148))
- Add functionality to anomac to download wasms for a given chain
  ([#1159](https://github.com/anoma/anoma/pull/1159))
- Improved CLI experience for 'anomaw address find'
  ([#1161](https://github.com/anoma/anoma/pull/1161))
- Wallet: Increase the number of iterations used for keys encryption to the
  recommended value. ([#1168](https://github.com/anoma/anoma/issues/1168))
- Improve the error message that is displayed when anoma binaries are run without
  having joined a chain ([#1176](https://github.com/anoma/anoma/pull/1176))
- Refactored ledger startup code
  ([#1231](https://github.com/anoma/anoma/pull/1231))
- Replace Tendermint consensus evidence parameters with
  application level evidence filter for outdated evidence.
  ([#1248](https://github.com/anoma/anoma/pull/1248))

### MISCELLANEOUS

- Updated rockDB dependency to 0.19.0 and enabled its jemalloc feature.
  ([#452](https://github.com/anoma/namada/pull/452))
- Removed intent gossiper and matchmaker code
  ([#493](https://github.com/anoma/namada/issues/493))
- Use a cargo workspace for some of our wasm crates
  ([#1096](https://github.com/anoma/anoma/pull/1096))
- Added a make recipe to build WASM in debug mode with `make debug-wasm-scripts`
  ([#1243](https://github.com/anoma/anoma/pull/1243))

### TESTING

- Test PoS transaction for bonding, unbonding and withdrawal. Fixed an issue
  found on unbonding. ([#462](https://github.com/anoma/anoma/issues/462))
- Fix a condition in tx_bond test that causes a false negative result
  ([#590](https://github.com/anoma/namada/pull/590))
- Fixed ANOMA_E2E_KEEP_TEMP=true to work in e2e::setup::network
  ([#1221](https://github.com/anoma/anoma/issues/1221))

## v0.7.1

Namada 0.7.1 is a patch release of the Namada software, continuing the
version numbering sequence previously used in the Anoma repository.
There are few important user-facing changes, but this is the first
tagged release in the Namada repository.

### CI

- New CI using Github Actions
  ([#222](https://github.com/anoma/namada/pull/222))

### DOCS

- Added OpenAPI spec ([#322](https://github.com/anoma/namada/pull/322))
- Applied various fixes and updates to the PoS system spec and integration spec
  ([#1070](https://github.com/anoma/anoma/pull/1070))
- Fixes libraries doc typos and correct comment on the clap crate
  ([#1143](https://github.com/anoma/anoma/pull/1143))

### FEATURES

- Added secp256k1 support ([#278](https://github.com/anoma/anoma/pull/278))

### IMPROVEMENTS

- Zeroize secret keys from memory
  ([#277](https://github.com/anoma/namada/pull/277))
- Better logging for end-to-end tests, and logs are
  stored to disk in the test's temporary working directory
  ([#1202](https://github.com/anoma/anoma/pull/1202))
- Hidden the stdout of Tendermint process by default. To include
  it in the node's output, run with `ANOMA_TM_STDOUT=true`
  ([#1239](https://github.com/anoma/anoma/pull/1239))

### MISCELLANEOUS

- Make some .gitignore patterns relative to repo root
  ([#1158](https://github.com/anoma/anoma/pull/1158))

### TESTING

- E2E: Consume unread output before checking exit status.
  ([#247](https://github.com/anoma/namada/pull/247))
- Switch back from a fork to a newly released version of expectrl
  ([#1142](https://github.com/anoma/anoma/pull/1142))

## v0.6.1

Anoma 0.6.1 is a patch release updating the Rust toolchain and various
libraries.

### BUG FIXES

- Fixed PoS `votes_per_token` parameter update validation
  ([#1181](https://github.com/anoma/anoma/issues/1181))

### IMPROVEMENTS

- Ledger: Updated the version of Tendermint used for ABCI++ ([#1088](https://github.com/anoma/anoma/pull/1088))
    - Add full support for ProcessProposal and FinalizeBlock
    - Updated the shims
    - Updated `tendermint-rs`, `ibc-rs`, and `tower-abci` deps
    - Updated the proto definitions
    - Added Tendermint's new method of a BFT timestamping
    - Updated the format of Tendermint's new config
    - Fixed booting up the tendermint node in the ledger with correct settings
    - Refactored storage to account for the fact that tendermint no longer passes in block headers
- Client: Configured Tendermints new event log and JSON RPC API for events querying ([#1088](https://github.com/anoma/anoma/pull/1088))
    - Added necessary config parameters to our tendermint node's configuration
    - Wrote a jsonrpc client for querying tendermint's event logs
    - Refactored how txs are submitted in the client when the `ABCI-plus-plus` feature is
      set to use jsonrpc calls instead of websockets.

### MISCELLANEOUS

- Updated RocksDB dependency version to v0.18.0
  ([#1135](https://github.com/anoma/anoma/issues/1135))

## v0.6.0

Anoma 0.6.0 is a scheduled minor release.

### BUG FIXES

- Ledger: Set the counterparty connection ID when the connection ack
  ([#968](https://github.com/anoma/anoma/issues/968))
- Ledger: Set the counterparty channel ID when the ack
  ([#980](https://github.com/anoma/anoma/issues/980))
- Ledger: Encode a commitment with Protobuf
  ([#988](https://github.com/anoma/anoma/issues/988))
- Client: Fix Tendermint node ID derivation from ed25519 keys in "utils init-
  network" command ([#992](https://github.com/anoma/anoma/issues/992))
- Ledger: Reuse IBC port ([#1011](https://github.com/anoma/anoma/issues/1011))
- Ledger: Fix to write the initial value of IBC sequence
  ([#1014](https://github.com/anoma/anoma/issues/1014))
- Fixes installation of Tendermint on M1 Macs
  ([#1018](https://github.com/anoma/anoma/issues/1018))
- Ledger: Fix IBC VP for packet timeout
  ([#1029](https://github.com/anoma/anoma/issues/1029))
- Ledger: Fix vp read_pre to read from write_log for the previous txs updates
  ([#1032](https://github.com/anoma/anoma/issues/1032))
- Ledger: Fix IBC token VP ([#1040](https://github.com/anoma/anoma/issues/1040))
- Fix loading of validator VP during chain initialization
  ([#1054](https://github.com/anoma/anoma/pull/1054))
- Fix possible overflow when formatting token amount to a string.
  ([#1087](https://github.com/anoma/anoma/pull/1087))

### DOCS

- Add docs for internal testnet for MASP
  ([#1013](https://github.com/anoma/anoma/pull/1013))
- Applied various fixes to MASP internal testnet guide
  ([#1017](https://github.com/anoma/anoma/pull/1017))
- Added docs page for testnet launch procedure.
  ([#1028](https://github.com/anoma/anoma/pull/1028))
- Add links to doc pages sources on Github.
  ([#1030](https://github.com/anoma/anoma/pull/1030))
- User guide and testnets documentation has been
  separated and moved to <https://github.com/anoma/docs>
  ([#1080](https://github.com/anoma/anoma/issues/1080))
- Updated whitepaper and vision paper links
  ([#1116](https://github.com/anoma/anoma/issues/1116))
- Install mdbook-admonish plugin
  ([#1132](https://github.com/anoma/anoma/pull/1132))
- Include Rust nightly version from root file
  ([#1133](https://github.com/anoma/anoma/pull/1133))

### FEATURES

- Client: Add raw bytes query command "query-bytes" from the storage.
  ([#836](https://github.com/anoma/anoma/issues/836))
- Added on-chain and off-chain governance validity predicate with client support
  for submitting proposal transaction, proposal queries and for creating off-
  chain proposals. ([#954](https://github.com/anoma/anoma/pull/954))
- Ledger: Change the storage hasher to SHA256
  ([#968](https://github.com/anoma/anoma/issues/968))
- Governance: Added proposal vote transaction and validity
  predicate support. Also improved the proposal query command.
  ([#975](https://github.com/anoma/anoma/pull/975))
- Ledger: Query with the specified height
  ([#987](https://github.com/anoma/anoma/issues/987))
- Add stub EthBridge internal address
  ([#1066](https://github.com/anoma/anoma/pull/1066))

### IMPROVEMENTS

- Ledger: The validity predicate checks rule has been simplified
  so that every validity predicate triggered by a transaction
  receives all the storage keys touched by the transaction.
  ([#955](https://github.com/anoma/anoma/issues/955))
- Ledger: write/get block header to get an old consensus state
  ([#974](https://github.com/anoma/anoma/issues/974))
- Ledger: Use non-validator full node Tendermint mode by default.
  ([#978](https://github.com/anoma/anoma/pull/978))
- Client: Updated the utils commands `init-genesis-validator` and `join-
  network` to be able to automatically configure a genesis validator node.
  ([#997](https://github.com/anoma/anoma/pull/997))
- Show an error when calling `anomac utils join-network` if trying to download a
  file and it is missing ([#1044](https://github.com/anoma/anoma/pull/1044))
- Wallet: various store and API changes and additions for genesis setup.
  ([#1063](https://github.com/anoma/anoma/pull/1063))

### MISCELLANEOUS

- Fixed Nix build and updated Nix dependencies.
  ([#994](https://github.com/anoma/anoma/pull/994))
- Update `make install` command to respect the Cargo.lock file
  ([#1118](https://github.com/anoma/anoma/issues/1118))

### TESTING

- Replaced E2E tests command runner library with
  [expectrl](https://crates.io/crates/expectrl)
  ([#686](https://github.com/anoma/anoma/issues/686))
- Added state-machine property-based tests for PoS validity predicate.
  ([#927](https://github.com/anoma/anoma/pull/927))
- WASM host environment testing helpers are now pinned to a stable
  memory location to avoid issues in state machine test runner.
  ([#947](https://github.com/anoma/anoma/pull/947))
- More logging in end-to-end tests
  ([#1071](https://github.com/anoma/anoma/pull/1071))

## v0.5.0

Anoma 0.5.0 is a scheduled minor release.

### BUG FIXES

- WASM: Fix WASM cache exponential backoff
  ([#834](https://github.com/anoma/anoma/issues/834))
- Ledger: Temporarily downgrade back to wasmer v1.0.2 until
  [the leak that is affecting Linux](https://github.com/anoma/anoma/issues/871) 
  is found and fixed. ([#870](https://github.com/anoma/anoma/pull/870))
- Ledger: Upgrade to wasmer v2.2.0 and fix memory leak
  caused by a circular reference in the WASM memory
  ([#871](https://github.com/anoma/anoma/issues/871))
- Change the validity predicate main entry-point function to receive
  `changed_keys` and `verifiers` arguments in a deterministic order.
  ([#891](https://github.com/anoma/anoma/issues/891))
- Dependency: Backport libp2p-noise patch that fixes a compilation
  issue from <https://github.com/libp2p/rust-libp2p/pull/2264>
  ([#908](https://github.com/anoma/anoma/issues/908))
- Wasm: Re-add accidentaly removed `tx_ibc` WASM and `vm_env::ibc` module
  ([#916](https://github.com/anoma/anoma/pull/916))
- Ledger & Matchmaker: In "dev" chain with "dev" build, load WASM directly from
  the root `wasm` directory. ([#933](https://github.com/anoma/anoma/issues/933))
- Ledger: Decode signed data in IBC VPs
  ([#938](https://github.com/anoma/anoma/issues/938))
- Ledger: Fixed handling of the Tendermint mode global argument.
  ([#943](https://github.com/anoma/anoma/pull/943))
- Ledger: Set IBC event besides tx_result
  ([#944](https://github.com/anoma/anoma/issues/944))
- Ledger: Fix IBC ClientReader functions
  ([#949](https://github.com/anoma/anoma/issues/949))
- Ledger: Set 0 as IBC height revision number
  ([#950](https://github.com/anoma/anoma/issues/950))
- Ledger: Fix the path via ABCI query
  ([#958](https://github.com/anoma/anoma/issues/958))

### CI

- Move cron pipeline script externally, fix cron scripts dependencies
  ([#906](https://github.com/anoma/anoma/pull/906))
- Fix cron scripts execution ([#912](https://github.com/anoma/anoma/pull/912))
- Build docs without attempting to merge master
  ([#924](https://github.com/anoma/anoma/pull/924))

### DOCS

- Added specifications for ledger, RPC, default transactions
  and encoding, which is partially derived from code.
  ([#887](https://github.com/anoma/anoma/pull/887))

### FEATURES

- Added IBC transaction ([#411](https://github.com/anoma/anoma/issues/411))
- Ledger: Added validity predicate whitelist configurable for a network to limit which validity predicates are permitted ([#875](https://github.com/anoma/anoma/issues/875))
- Ledger: Added transaction whitelist configurable for a network to limit which transactions are permitted ([#876](https://github.com/anoma/anoma/issues/876))
- Added transactions and vp to create and mint nfts.
  ([#882](https://github.com/anoma/anoma/issues/882))
 - Supports a new type of transaction intended to be sent by validators, so called protocol transactions. 
   - New transaction type
   - Generation of keys for validators to sign protocol txs
   - A service to broadcast protocol txs from the ledger
   - Improved client tx broadcasting
     
   (#[913](https://github.com/anoma/anoma/pull/913))

### IMPROVEMENTS

- Added a common signing schemes interface to ease additions/removals of signing
  schemes to the ledger. ([#225](https://github.com/anoma/anoma/issues/225))
- Canonicalize all wallet aliases to lowercase in the CLI.
  ([#564](https://github.com/anoma/anoma/issues/564))
- Ledger: Handle spurious errors on user initiated shutdown.
  ([#716](https://github.com/anoma/anoma/issues/716))
- Dependency: Replace ed22519-dalek with ed22519-consensus.
  ([#753](https://github.com/anoma/anoma/issues/753))
- Network config: Make the WASM checksums optional in network source, as it is 
  filled in by `init-network` utils command.
  ([#777](https://github.com/anoma/anoma/issues/777))
- Network config: The WASM dir were moved inside chain directories.
  ([#838](https://github.com/anoma/anoma/issues/838))
- Ledger: added support for transactions to write temporary data that
  can be read by any VP that is checking the validity of the transaction.
  This is being used in IBC native VP for fungible token transfer.
  ([#848](https://github.com/anoma/anoma/pull/848))
- Ledger: Update tendermint-rs and ibc-rs
  ([#863](https://github.com/anoma/anoma/issues/863))
- Ledger: Sign transaction hash of bytes instead of the bytes themselves.
  ([#886](https://github.com/anoma/anoma/issues/886))
- Update the Rust toolchain to 1.58.1.
  ([#902](https://github.com/anoma/anoma/pull/902))
- Implemented `BorshSchema` for ledger's the public types.
  ([#907](https://github.com/anoma/anoma/pull/907))
- Updated the tx result from an undecryptable tx to give an error code and message stating message was not decryptable
  ([#910](https://github.com/anoma/anoma/pull/910))
- Ledger: Update ibc-rs to v0.12.0
  ([#926](https://github.com/anoma/anoma/issues/926))
- WASM: Use tx/VP specific preludes.
  ([#948](https://github.com/anoma/anoma/pull/948))
- WASM: Split up tx and VP modules into files.
  ([#952](https://github.com/anoma/anoma/pull/952))

## v0.4.0

Anoma 0.4.0 is a scheduled minor release, released 31 January 2022.

### BUG FIXES

- Matchmaker: Fix a matchmaker's state management via a raw pointer
  that was causing segfaults in the matchmaker in release build.
  ([#806](https://github.com/anoma/anoma/pull/806))

### CI

- Build Linux package directly from tagged releases, and upload wasm from tags.
  ([#801](https://github.com/anoma/anoma/pull/801))

### FEATURES

- Client/Ledger: Added a flag  to allow to indicate that client should exit once
  the transaction is in mempool without waiting for it to be applied in a block.
  ([#403](https://github.com/anoma/anoma/issues/403))
- Ledger: Emit and validate IBC events from transactions.
  ([#480](https://github.com/anoma/anoma/issues/480))
- Add `anomac tx-result` command to query the result of a transaction given a
  transaction hash. ([#634](https://github.com/anoma/anoma/issues/634))
- Ledger: Use IBC messages from ibc-rs crate to be used in the relayer.
  ([#699](https://github.com/anoma/anoma/issues/699))
- Ledger: Added [fungible token transfer](https://github.com/cosmos/ibc/tree/26299580866b80fbdf0ce8a0691ee19a28176795/spec/app/ics-020-fungible-token-transfer)
  support to IBC validity predicate. 
  ([#823](https://github.com/anoma/anoma/issues/823))

### IMPROVEMENTS

- Ledger: Add IbcActions trait to execute IBC operations
  ([#411](https://github.com/anoma/anoma/issues/411))
- Matchmaker has been separated from intent gossiper node. Multiple
  matchmakers can connect to an intent gossiper node over WebSocket.
  ([#579](https://github.com/anoma/anoma/issues/579))
- Wallet: Ask for encryption password confirmation when generating a new key.
  ([#625](https://github.com/anoma/anoma/issues/625))
- Ledger: Two-layer merkle tree for the IBC proof verification
  ([#671](https://github.com/anoma/anoma/issues/671))
- Testing: Increments network configuration ports used for E2E
  tests and ABCI++ enabled E2E tests to avoid sharing resources.
  ([#717](https://github.com/anoma/anoma/issues/717))
- Matchmaker: compiling and loading matchmakers to and from dylib instead of
  WASM ([#718](https://github.com/anoma/anoma/pull/718))
- Ledger: Coding IBC-related data without Borsh
  ([#734](https://github.com/anoma/anoma/issues/734))
- Matchmaker: re-purpose the matchmaker macro to manage state of a custom
  matchmaker implementation ([#746](https://github.com/anoma/anoma/pull/746))
- Testing: Update to a new branch of property-based state machine testing with
  initial state shrinking. ([#765](https://github.com/anoma/anoma/pull/765))
- Port the Nix build to the new Flakes system.
  ([#770](https://github.com/anoma/anoma/pull/770))
- Client/Utils: Respect wasm directory, when specified and non-default in the
  command. The command now doesn't unpack the network config archive into its
  default directories, if any of them are specified with non-default values.
  ([#813](https://github.com/anoma/anoma/issues/813))
- Install the default token exchange matchmaker implemenetation into
  `~/.cargo/lib` directory when building from source. When not absolute, the
  matchmaker will attempt to load the matchmaker from the same path as where the
  binary is being ran from, from `~/.cargo/lib` or the current working 
  directory. ([#816](https://github.com/anoma/anoma/issues/816))

### MISCELLANEOUS

- Force non-dev build for make build-release, check-release & package
  ([#791](https://github.com/anoma/anoma/pull/791))

## v0.3.1

Anoma 0.3.1 - first maintenance release in the 0.3.x series. Protocol
compatible with 0.3.0, but changes the on-disk storage format - nodes
will need to resync from scratch.

### BUG FIXES

- Fix the `anoma client utils join-network` to respect `--base-dir` argument, if
  specified ([#723](https://github.com/anoma/anoma/issues/723))
- Ledger: Fix an issue in the default thread count usage calculation that
  was previously causing it to crash for a target with a single logical core.
  ([#726](https://github.com/anoma/anoma/pull/726))
- Ledger: write storage diffs from the correct current block height and ignore
  these on loading last known block's state from persisted state on disk.
  ([#732](https://github.com/anoma/anoma/pull/732))
- Ledger: Handle Unix and Windows interrupt and termination signals to shut down
  cleanly. ([#768](https://github.com/anoma/anoma/issues/768))

### IMPROVEMENTS

- Ledger: enable atomic commits in RocksDB and explicitly flush blocks without
  waiting ([#372](https://github.com/anoma/anoma/issues/372))
- Fix the `anoma client utils join-network` to respect `--base-dir` argument, if
  specified ([#711](https://github.com/anoma/anoma/issues/711))
- Ledger: Write predecessor block's values to be able to integrate Tendermint's
  rollback helper command. ([#729](https://github.com/anoma/anoma/pull/729))
- Include a more accurate build version from git describe in help output version
  strings. ([#733](https://github.com/anoma/anoma/pull/733))
- Ledger: Updated wasmer dependency to [v2.1.1](https://github.com/wasmerio/wasmer/releases/tag/2.1.1).
  ([#756](https://github.com/anoma/anoma/pull/756))
- Config: Enable setting config values via environment variables, add
  variables for configuring Tendermint instrumentation and allow missing
  values in the config file (filled in with defaults defined in the code)
  ([#774](https://github.com/anoma/anoma/pull/774))
- Gossip: Enable peer discovery with libp2p Kademlia and Identify
  protocol and allow to keep the established peer connections open.
  ([#775](https://github.com/anoma/anoma/pull/775))

### MISCELLANEOUS

- Adds missing nix-shell openssl dependency.
  ([#694](https://github.com/anoma/anoma/pull/694))
- Don't include wasm checksums in the package, since the network configuration
  mechanisms now handle this. ([#731](https://github.com/anoma/anoma/pull/731))
- Force non-dev build for make clippy.
  ([#783](https://github.com/anoma/anoma/pull/783))

## v0.3.0

Anoma 0.3.0

### BUG FIXES

- Ledger: Using fixes in `tower-abci` crate that improve shutdown and error handling.
  ([#614](https://github.com/anoma/anoma/pull/614))
- Ledger: Fix rlimit breaking build on non-unix target.
  ([#615](https://github.com/anoma/anoma/pull/615))
- Ledger/client: Fixed an issue with obtaining a result of a transaction.
  ([#668](https://github.com/anoma/anoma/pull/668))
- Ledger: Fixed Windows build. ([#684](https://github.com/anoma/anoma/pull/684))
- Use at least one thread for rocksdb compaction.
  ([#704](https://github.com/anoma/anoma/pull/704))
- Downgrade to an older version of wasmer (1.0.2) to avoid runaway memory usage.
  ([#708](https://github.com/anoma/anoma/pull/708))
- Process ABCI requests in order in the shell.
  ([#713](https://github.com/anoma/anoma/pull/713))

### CI

- Added jobs for ABCI++ feature enabled builds
  ([#661](https://github.com/anoma/anoma/pull/661))

### DOCS

- Fix broken links ([#605](https://github.com/anoma/anoma/issues/605))
- Improved user guide installation section. Improved development scripts.
  ([#613](https://github.com/anoma/anoma/pull/613))
- Updated Anoma prototypes pages.
  ([#642](https://github.com/anoma/anoma/pull/642))
- Fix broken links to WASM sources.
  ([#660](https://github.com/anoma/anoma/pull/660))

### FEATURES

- Ledger: Added storage query (non-)membership proofs
  ([#498](https://github.com/anoma/anoma/issues/498))
- Ledger: Make all transactions encrypted, add in ABCI++, support commit and
  reveal scheme for txs in a block. This feature is disabled by default
  because it requires a custom Tendermint build. The Tendermint version
  required with default features remains unchanged (currently 0.34.x).
  ([#622](https://github.com/anoma/anoma/pull/622))
- Cache compiled wasm modules on disk.
  ([#697](https://github.com/anoma/anoma/pull/697))

### IMPROVEMENTS

- Improve how the `anoma` binary launches a sub-process by replacing itself with
  it. ([#609](https://github.com/anoma/anoma/pull/609))
- Ledger/client: Add archives for release-able networks from init-network utils
  command. ([#616](https://github.com/anoma/anoma/pull/616))
- Ledger: Open the default P2P address for non-localhost networks
  ([#617](https://github.com/anoma/anoma/pull/617))
- Tooling (switched to Rust 1.56.1 and nightly  to 2021-11-01. Many Cargo
  dependencies updates. ([#618](https://github.com/anoma/anoma/pull/618))
- Ledger: Join Anoma networks from GitHub released network configurations.
  ([#619](https://github.com/anoma/anoma/pull/619))
- Ledger/storage: Write values from references.
  ([#627](https://github.com/anoma/anoma/pull/627))
- Build: Avoid build context in Docker image builds.
  ([#629](https://github.com/anoma/anoma/pull/629))
- Ledger: Add the WASM checksums file for the pre-built
  transactions and validity predicates to network releases.
  ([#644](https://github.com/anoma/anoma/pull/644))
- Ledger: Simplified gas addition code. ([#648](https://github.com/anoma/anoma/pull/648))
- Ledger: Improved the "wrapper" transaction type data structures and encoding.
  ([#653](https://github.com/anoma/anoma/pull/653))
- Ledger: Follow-up to the improved "wrapper" transaction type data structures
  and encoding. ([#655](https://github.com/anoma/anoma/pull/655))
- Ledger: Refactored ledger threads usage and made them configurable.
  ([#658](https://github.com/anoma/anoma/pull/658))
- Ledger: Updated dependencies names to nix friendly format.
  ([#664](https://github.com/anoma/anoma/pull/664))
- Ledger: Follow-up to the updated crate names to nix friendly format.
  ([#666](https://github.com/anoma/anoma/pull/666))
- Ledger/client: Set a default fee amount, token, and gas limit for txs.
  ([#667](https://github.com/anoma/anoma/pull/667))
- Remove intent gossiper key from configuration file, storing it separately.
  ([#673](https://github.com/anoma/anoma/pull/673))
- Refactor historical data storage in rocksdb to store diffs
  of key changes, and additional database performance changes.
  ([#683](https://github.com/anoma/anoma/pull/683))
- Improved nix integration. ([#685](https://github.com/anoma/anoma/pull/685))
- Ledger/client: Fix the confirmation dialog for using an existing alias and
  allow to select a new one. ([#690](https://github.com/anoma/anoma/pull/690))
- Refactor debug printouts in wasm modules to use conditional compilation.
  ([#693](https://github.com/anoma/anoma/pull/693))
- Ledger: Updated to wasmer 2.0.1.
  ([#698](https://github.com/anoma/anoma/pull/698))
- Allow zero-balance transactions pending proper gas fee deduction.
  ([#700](https://github.com/anoma/anoma/pull/700))
- Emit more CPU thread usage information.
  ([#705](https://github.com/anoma/anoma/pull/705))

### TESTING

- Tests/E2E: Added PoS tests for bonding and initialization of a validator
  account on-chain. ([#463](https://github.com/anoma/anoma/issues/463))

