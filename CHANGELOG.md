# CHANGELOG

## v0.31.9

Namada 0.31.9 is a patch release that includes a fix of IBC timestamp, transaction gas cost and shielded context for dry-ran transactions and RocksDB update.

### BUG FIXES

- Fix the timeout timestamp for PGF over IBC
  ([\#2774](https://github.com/anoma/namada/issues/2774))
- Fixed a bug in the client for which the speculative
  shielded context was updated event in a dry run.
  ([\#2775](https://github.com/anoma/namada/pull/2775))
- Restore the IBC tx gas cost to match the version 0.31.6.
  ([\#2824](https://github.com/anoma/namada/pull/2824))

### IMPROVEMENTS

- Improve build time of git2 dependency by disabling the default features.
  ([\#2724](https://github.com/anoma/namada/pull/2724))
- Various client improvements.
  ([\#2748](https://github.com/anoma/namada/pull/2748))
- Updated RocksDB dependency. For a shared libary users make sure to link
  against version v8.10.0. ([\#2776](https://github.com/anoma/namada/pull/2776))

### SDK

- `gen_shielded_transfer` now takes an extra `update_ctx`
  argument to conditionally update the shielded context.
  ([\#2775](https://github.com/anoma/namada/pull/2775))

### TESTING

- Fix E2E test for PGF over IBC
  ([\#2765](https://github.com/anoma/namada/issues/2765))

## v0.31.8

Namada 0.31.8 is a patch release that prevents issues with incompatible WASM compilation cache and other minor issues.

### BUG FIXES

-  Downgrade nightly toolchain to `2024-02-10`.
  ([\#2761](https://github.com/anoma/namada/pull/2761))

### IMPROVEMENTS

- Added WASM cache versioning to avoid issues on updates that don't have
  compatible binary format. ([\#2757](https://github.com/anoma/namada/pull/2757))

### SDK

- Make more MASP types public.
  ([\#2762](https://github.com/anoma/namada/pull/2762))

## v0.31.7

Namada 0.31.7 is a patch release that contains code refactors, various fixes and improvements.

### BUG FIXES

- Fix ibc-gen-shielded for shielded transfers back to the origin
  ([\#2634](https://github.com/anoma/namada/issues/2634))
- Fixed the default `--node` argument when no specified.
  ([\#2701](https://github.com/anoma/namada/pull/2701))
- Bail from router if a nester router segment is not matched.
  ([\#2739](https://github.com/anoma/namada/pull/2739))

### IMPROVEMENTS

- Refactored sub-systems integration in the ABCI FinalizeBlock request handler.
  ([\#2482](https://github.com/anoma/namada/pull/2482))
- Refactored token crates. ([\#2493](https://github.com/anoma/namada/pull/2493))
- Refactored core crate to flatten the modules structure.
  ([\#2503](https://github.com/anoma/namada/pull/2503))
- Refactored governance crate dependencies.
  ([\#2506](https://github.com/anoma/namada/pull/2506))
- Hid addresses used for testing from public API.
  ([\#2507](https://github.com/anoma/namada/pull/2507))
- Expanded the variety of test vectors generated for hardware
  wallets and simplified their format in some places.
  ([\#2588](https://github.com/anoma/namada/pull/2588))
- Refactored the state crate.
  ([\#2606](https://github.com/anoma/namada/pull/2606))
- Add slashed bonds/unbonds info to the client.
  ([\#2670](https://github.com/anoma/namada/pull/2670))
- Moving to rust version 1.76.0 ([#2687](https://github.com/anoma/anoma/pull/2687))

### TESTING

- Implemented mock transaction prover and verifier for faster testing and lower
  development time. ([\#2695](https://github.com/anoma/namada/pull/2695))

## v0.31.6

Namada 0.31.6 is a patch release that contains various fixes and improvements.

### BUG FIXES

- Fix shielded balance query for IBC tokens
  ([\#2625](https://github.com/anoma/namada/issues/2625))
- Rather than allowing CometBFT to keep processing blocks after a storage write
  has failed in Namada, crash the ledger to avoid any potential corruption of
  state. ([\#2657](https://github.com/anoma/namada/pull/2657))
- Fixing the order of proposal execution to be deterministic.
  ([\#2679](https://github.com/anoma/namada/pull/2679))

### FEATURES

- Added wallet command to "convert" a consensus key
  into Tendermint private validator key JSON format.
  ([\#2516](https://github.com/anoma/namada/pull/2516))

### IMPROVEMENTS

- Simplified the transaction fetching algorithm to enable it to be saved to
  storage more frequently. ([\#2458](https://github.com/anoma/namada/pull/2458))
- The client, when generating a shielded transfer, invalidates the
  masp notes that have been spent without the need to sync with a node.
  ([\#2534](https://github.com/anoma/namada/pull/2534))
- CLI: Allow to use global args (`--chain-id`, `--base-dir`, `--wasm-dir` and 
  `--pre-genesis`) before or after a sub-command.
  ([\#2545](https://github.com/anoma/namada/pull/2545))
- Show help message for query-proposal subcommand instead of crashing when no
  arg provided. ([\#2611](https://github.com/anoma/namada/pull/2611))
- Various improvements to client and error logging.
  ([\#2615](https://github.com/anoma/namada/pull/2615))
- Allow users to input http/https url as ledger urls.
  ([\#2658](https://github.com/anoma/namada/pull/2658))
- Increase broadcaster timeout and allow users to increase it via environment
  variable. ([\#2668](https://github.com/anoma/namada/pull/2668))

### SDK

- Reworked the sdk to support the new speculative state of the
  `ShieldedContext`:\n-`ShieldedContext` now has an extra field to determin its
  state\n-When calling `gen_shielded_transfer` the context now invalidates the
  spent notes (if any)\n-The fee unshielding `Transaction` is now built before
  the actual transaction\n-`find_viewing_key` only requires a shared reference
  now ([\#2534](https://github.com/anoma/namada/pull/2534))

## v0.31.5

Namada 0.31.5 is a patch release that fixes consensus validator set update for CometBFT.

### BUG FIXES

- Fixed a bug in the communication of validator set updates to
  CometBFT after a change of validator consensus key that occurs
  at the same epoch as a validator entering the consensus set.
  ([\#2653](https://github.com/anoma/namada/pull/2653))

## v0.31.4

Namada 0.31.4 is a patch release that fixes the result query of an active governance proposal.

### BUG FIXES

- Fixes the query-proposal-result output in the case that a proposal is still
  voting. ([\#2573](https://github.com/anoma/namada/pull/2573))

## v0.31.3

Namada 0.31.3 is a patch release that fixes various issues.

### BUG FIXES

- Fix PoS bonds and unbonds query to return delegations when only a validator
  address is specified. ([\#2522](https://github.com/anoma/namada/pull/2522))
- PoS: fixed the order of iteration when slashing validators for liveness.
  ([\#2577](https://github.com/anoma/namada/pull/2577))
- Reject validator set updates signing over a superset of the next validator
  set. ([\#2578](https://github.com/anoma/namada/pull/2578))
- Governance tallying for delegators now works.
  ([\#2579](https://github.com/anoma/namada/pull/2579))

### IMPROVEMENTS

- Adds some useful internal addresses, such as PoS, to the wallet upon join-
  network. ([\#2543](https://github.com/anoma/namada/pull/2543))
- Fixes query-protocol-parameters to include some missing PoS data and a better-
  formatted output. ([\#2558](https://github.com/anoma/namada/pull/2558))

## v0.31.2

Namada 0.31.2 is a patch release that fixes an issue with request ordering introduced in 0.31.1.

### BUG FIXES

- ABCI calls must be executed synchronously.
  ([\#2547](https://github.com/anoma/namada/pull/2547))

### FEATURES

- Added a client command "status" to query a node's status.
  ([\#2511](https://github.com/anoma/namada/pull/2511))

## v0.31.1

Namada 0.31.1 is a patch release that fixes the memo processing for some transactions and improves logs related to ledger startup and the wallet.

### BUG FIXES

- Wallet: respect the optional bip39-flag for key derivation.
  ([\#2489](https://github.com/anoma/namada/pull/2489))

### IMPROVEMENTS

- Wallet: print the generated payment address.
  ([\#2490](https://github.com/anoma/namada/pull/2490))
- Reworks the way the ledger waits for genesis start. It now fully initializes the node and 
  outputs logs before sleeping until genesis start time. Previously it would not start any 
  processes until genesis times, giving no feedback to users until genesis time was reached.
  ([\#2502](https://github.com/anoma/namada/pull/2502))

## v0.31.0

Namada 0.31.0 is a minor release that fixes wasm host function execution and upgrades some CLI functions and the Masp VP.

### BUG FIXES

- Use the configured native token for genesis validation.
  ([\#2471](https://github.com/anoma/namada/pull/2471))
- Wallet: handle the case when empty decryption password is provided.
  ([\#2473](https://github.com/anoma/namada/pull/2473))
- Avoid panic in host env functions
  ([\#2478](https://github.com/anoma/namada/issues/2478))

### IMPROVEMENTS

- Removed possible over/under-flow of `I128Sum` operations in the masp vp.
  ([\#2476](https://github.com/anoma/namada/pull/2476))

## v0.30.3

Namada 0.30.3 is a patch release that refactors some MASP functionality and fixes some governance and CLI issues.

### BUG FIXES

- Fixing several bugs in how governance and pgf transactions are handled and
  validated. ([\#2459](https://github.com/anoma/namada/pull/2459))

### IMPROVEMENTS

- Modified the MASP VP to validate the changed storage keys instead of the
  `Transfer` object. ([\#2452](https://github.com/anoma/namada/pull/2452))
- MASP inflation for a given token now is adjusted based on a target amount
  of total locked (shielded) tokens rather than a ratio relative to some total
  supply. ([\#2460](https://github.com/anoma/namada/pull/2460))
- Add an address CLI arg that defaults to the native token.
  ([\#2467](https://github.com/anoma/namada/pull/2467))

### SDK

- Modified `scan_tx` to require the set of changed keys instead of `Transfer`.
  `fetch_shielded_transfer` now returns the set of changed keys instead of
  `Transfer`. ([\#2452](https://github.com/anoma/namada/pull/2452))

## v0.30.2

Namada 0.30.2 is a patch release that contains various bug fixes and improvements.

### BUG FIXES

- Fixed possible panics in transaction host environment functions.
  ([\#2401](https://github.com/anoma/namada/pull/2401))
- Fix the token burn function.
  ([\#2408](https://github.com/anoma/namada/pull/2408))
- Improving code around governance tally computations.
  ([\#2415](https://github.com/anoma/namada/pull/2415))
- Fix the MASP VP to enable changes to the shielded set max reward rate for a
  token. ([\#2424](https://github.com/anoma/namada/pull/2424))
- Validates changes to the balance key in masp vp.
  ([\#2428](https://github.com/anoma/namada/pull/2428))
- Restrict the reward distribution of a steward to a maximum of 100.
  ([\#2440](https://github.com/anoma/namada/pull/2440))
- Avoid diff overflow in Multitoken VP
  ([\#2443](https://github.com/anoma/namada/issues/2443))
- Restricted RPC router paths to ASCII characters to prevent crashes.
  ([\#2447](https://github.com/anoma/namada/pull/2447))

### FEATURES

- Implemented ZIP32 functionality for shielded pool keys.
  ([\#2417](https://github.com/anoma/namada/pull/2417))

### IMPROVEMENTS

- Added tx WASM code allowlist at protocol level and VP WASM code allowlist in
  the host environment functions.
  ([\#2419](https://github.com/anoma/namada/pull/2419))
- The test vector generator now supports generating MASP transactions.
  ([\#2427](https://github.com/anoma/namada/pull/2427))
- Disabled RocksDB jemalloc feature by default for non-release builds.
  ([\#2404](https://github.com/anoma/namada/pull/2404))
- Skip writing some MASP and IBC storage keys to merkle tree and DB diffs.
  ([\#2438](https://github.com/anoma/namada/pull/2438))
- BIP39 passphrase made optional.
  ([\#2442](https://github.com/anoma/namada/pull/2442))

### SDK

- Both the `reading` and `writing` modules of the light SDK can now be used from
  within an async runtime. ([\#2399](https://github.com/anoma/namada/pull/2399))

### TESTING

- Added an integration test to verify that unconverted asset types can be spent
  in the MASP. ([\#2406](https://github.com/anoma/namada/pull/2406))

## v0.30.1

Namada 0.30.1 is a patch release that contains various bug fixes for MASP, IBC, the shell and crates refactor (the core has been subdivided into many smaller crates).
<!--
    Add a summary for the release here.

    If you don't change this message, or if this file is empty, the release
    will not be created. -->

### IMPROVEMENTS

- Refactored the core crate into many smaller crates.
  ([\#2312](https://github.com/anoma/namada/pull/2312))
- Strengthened the checks in the MASP VP. Allow viewing and spending of
  unconvertible MASP notes ([\#2371](https://github.com/anoma/namada/pull/2371))
- Refactored the fee validation process.
  ([\#2382](https://github.com/anoma/namada/pull/2382))
- Updated block validation to require a valid timestamp.
  ([\#2383](https://github.com/anoma/namada/pull/2383))
- Moved Rust crates into a crates sub-dir.
  ([\#2386](https://github.com/anoma/namada/pull/2386))
- Ibc transactions can be rewrapped in case of a gas error.
  ([\#2395](https://github.com/anoma/namada/pull/2395))

### SDK

- Added some more RPC methods for computing governance proposal
  results, query pgf parameters and total supply of a token.
  ([\#2400](https://github.com/anoma/namada/pull/2400))

### TESTING

- Fix E2E test for PGF over IBC by waiting before checking the balance
  ([\#2398](https://github.com/anoma/namada/issues/2398))

## v0.30.0

Namada 0.30.0 is a minor release that primarily upgrades the MASP and WASM VM memory functionality in addition to smaller upgrades to other Namada modules.

### BUG FIXES

- Suppress querying errors when a user has no token balance
  ([\#1910](https://github.com/anoma/namada/issues/1910))
- Fix alignment errors on wasmer that cause the ledger to crash.
  ([\#2384](https://github.com/anoma/namada/pull/2384))
- Sanitize wasm memory accesses which are outside of the 32-bit address
  range, to avoid crashing the ledger while executing malicious wasm payloads.
  ([\#2385](https://github.com/anoma/namada/pull/2385))

### FEATURES

- PGF over IBC ([\#1395](https://github.com/anoma/namada/issues/1395))

### IMPROVEMENTS

- Adds a new `query_proposal_votes` query, improves the formatting of
  `ProposalResult` and returns early in client if governance voter has no stake.
  Misc refactors. ([\#2330](https://github.com/anoma/namada/pull/2330))
- Removes panics from masp vp. Refactors masp storage keys generation.
  ([\#2345](https://github.com/anoma/namada/pull/2345))
- Introduce a memo field, to allow including arbitrary data inside of
  transactions. ([\#2358](https://github.com/anoma/namada/pull/2358))
- Include validator avatar url in their medatada
  ([\#2359](https://github.com/anoma/namada/pull/2359))
- Removed masp data from storage. Updated the client to query the cometBFT rpc
  endpoints. ([\#2363](https://github.com/anoma/namada/pull/2363))
- When constructing a governance proposal the id is now a required field.
  ([\#2365](https://github.com/anoma/namada/pull/2365))
- Added validator's consensus key look-up to `client find-validator`
  command, which now also accepts a native validator address.
  ([\#2368](https://github.com/anoma/namada/pull/2368))
- Fix the function `bond_amount` to more accurately account for slashes.
  ([\#2374](https://github.com/anoma/namada/pull/2374))
- The MASP VP now validates the tx expiration.
  ([\#2375](https://github.com/anoma/namada/pull/2375))
- Removed the hardcoded sentinel key of MASP.
  ([\#2376](https://github.com/anoma/namada/pull/2376))
- Improved governance variable names and code reuse.
  ([\#2377](https://github.com/anoma/namada/pull/2377))

### SDK

- Added `QueryProposalVotes` struct. Removes `VoteType`from
  the `Display` implementation of `LedgerProposalVote`. Updates
  `build_vote_proposal` to return an error if voter has no delegations.
  ([\#2330](https://github.com/anoma/namada/pull/2330))
- Refactors MASP keys construction.
  ([\#2345](https://github.com/anoma/namada/pull/2345))
- Add optional memo field to transaction args.
  ([\#2358](https://github.com/anoma/namada/pull/2358))
- Modified `ShieldedContext` to use `IndexedTx` to track the last indexed
  masp tx. Updated `fetch_shielded_transfer` and `compute_pinned_balance`
  to query the cometBFT rpc endpoints to retrieve masp data.
  Updated `block_search` to accept a fallible cast to `Height`.
  ([\#2363](https://github.com/anoma/namada/pull/2363))
- Cleaned up the unused ibc dependency of the light sdk crate.
  ([\#2372](https://github.com/anoma/namada/pull/2372))
- `tx_signers` returns no signing key when the source of a transaction is MASP.
  ([\#2376](https://github.com/anoma/namada/pull/2376))

### TESTING

- Add IBC E2E test with Hermes
  ([\#773](https://github.com/anoma/namada/issues/773))

## v0.29.0

Namada 0.29.0 is a minor release that introduces the light SDK, upgrades the MASP and CLI, and includes other fixes and refactors of the PoS, IBC, and Ethereum Birdge modules.

### BUG FIXES

- Prevents double-spending in masp by adding a nullifier set.
  ([\#2240](https://github.com/anoma/namada/pull/2240))
- Updates masp tx to store the notes and the native vp to validate them and the
  anchors. ([\#2244](https://github.com/anoma/namada/pull/2244))
- Updates the masp vp to validate the convert description's anchor.
  ([\#2248](https://github.com/anoma/namada/pull/2248))
- Client: Check that transaction is successful before taking further actions.
  ([\#2279](https://github.com/anoma/namada/pull/2279))
- Non-Namada token can be given to ibc-gen-shielded
  ([\#2308](https://github.com/anoma/namada/issues/2308))
 - Make the ledger wait for genesis before starting up any processes ([\#2310](https://github.com/anoma/namada/pull/2310))

### FEATURES

- A new client command has been added that takes a set of pre-genesis template files, validates them,
and runs them through init_chain. All errors are collected into a report. ([\#2255](https://github.com/anoma/namada/pull/2255))
- The wallet CLI structure has been significantly reworked and simplified.
  Alias argument is now obligatory for key generation / derivation
  commands. Feature of raw (non-HD) key generation has been restored,
  which was removed in the previous release. Key export / import
  functionality for both transparent and shielded key kinds has been
  implemented. Additionally, several other improvements have been made.
  ([\#2260](https://github.com/anoma/namada/pull/2260))
- IBC transfer from a spending key
  ([\#2321](https://github.com/anoma/namada/issues/2321))

### IMPROVEMENTS

- Emit Bridge pool transfer status update events from FinalizeBlock
  ([\#1995](https://github.com/anoma/namada/pull/1995))
- Refactored module dealing with Tendermint configuration.
  ([\#2127](https://github.com/anoma/namada/pull/2127))
- The default implicit and established user account VPs now
  require valid signature(s) for unknown storage changes.
  ([\#2213](https://github.com/anoma/namada/pull/2213))
- Allowed the unshielding of previous epochs assets from the masp.
  ([\#2222](https://github.com/anoma/namada/pull/2222))
- Fee amounts in transaction wrappers are now denominated to facilitate hardware
  wallet support. ([\#2245](https://github.com/anoma/namada/pull/2245))
- Refactor the PoS crate by breaking up the lib and tests code into smaller
  files. ([\#2253](https://github.com/anoma/namada/pull/2253))
- Made test vector generation easier and reduced the difficulty of maintaining
  the generation code. ([\#2259](https://github.com/anoma/namada/pull/2259))
- Client: Improved output of transaction results.
  ([\#2276](https://github.com/anoma/namada/pull/2276))
- Enhances the speed of two PoS tests that run particularly longer than others
  in CI. ([\#2277](https://github.com/anoma/namada/pull/2277))
- Removed useless epoch for fee unshielding and refactored tests.
  ([\#2282](https://github.com/anoma/namada/pull/2282))
- Refactor internal structure of the Ethereum bridge crate
  ([\#2288](https://github.com/anoma/namada/pull/2288))
- Move Ethereum bridge transaction code from `apps` to the `ethereum_bridge`
  crate. ([\#2289](https://github.com/anoma/namada/pull/2289))
- Move the pos inflation gain parameters to the PosParams.
  ([\#2294](https://github.com/anoma/namada/pull/2294))
- Move the inflation code for PoS and PGF into their own native modules.
  ([\#2295](https://github.com/anoma/namada/pull/2295))
- Improved validation on transaction's expiration. Added an expiration for MASP
  transfers. ([\#2315](https://github.com/anoma/namada/pull/2315))

### IMPROVMENTS

- Previously, a hardcoded set of tokens were expected to be used in Masp conversions.
  If these tokens did not have configs in genesis, this would lead to a panic after the first
  epoch change. This PR fixes this to use the tokens found in genesis belonging to the MASP
  rewards whitelist instead of hardcoding the tokens.
  ([\#2285](https://github.com/anoma/namada/pull/2285))

### SDK

- Introduce a method to query the status (pending, relayed or expired) of Bridge
  pool transfers ([\#1995](https://github.com/anoma/namada/pull/1995))
- Added light sdk ([\#2220](https://github.com/anoma/namada/pull/2220))
- Improved the TxResponse type.
  ([\#2276](https://github.com/anoma/namada/pull/2276))
- Removed useless epoch for fee unshielding.
  ([\#2282](https://github.com/anoma/namada/pull/2282))
- ibc-gen-shielded can set non-Namada token
  ([\#2308](https://github.com/anoma/namada/issues/2308))
- Updated `gen_shielded_transfer` to attach a sensible expiration to a MASP
  `Transaction`. ([\#2315](https://github.com/anoma/namada/pull/2315))
- ibc-transfer can set a spending key to the source
  ([\#2321](https://github.com/anoma/namada/issues/2321))

### TESTING

- Added e2e test for change-consensus-key command.
  ([\#2218](https://github.com/anoma/namada/pull/2218))

## v0.28.2

Namada 0.28.2 is a patch release that fixes a stack overflow issue for nodes.

### BUG FIXES

- Fixed DB prefix iterators to avoid iterators with key that don't match the
  given prefix, which was triggering recursive call that was growing stack with
  every new applied tx and on reading state from disk on start-up. Replaced
  recursion from RocksDB that was growing stack size with a loop.
  ([\#2325](https://github.com/anoma/namada/pull/2325))

## v0.28.1

Namada 0.28.1 is a patch release that makes improvements to the MASP, SDK, merkle trees, and chain initialization conditions.

### BUG FIXES

- Fix sdk compilation when using async-send feature flag.
  ([\#2261](https://github.com/anoma/namada/pull/2261))
- Added back missing changed storage keys in transaction results.
  ([\#2263](https://github.com/anoma/namada/pull/2263))
- Fix to skip pruning BridgePool Merkle trees when no signed nonce
  ([\#2264](https://github.com/anoma/namada/issues/2264))
- Initialize token total supply to zero at init chain.
  ([\#2270](https://github.com/anoma/namada/pull/2270))

### IMPROVEMENTS

- Preload and cache MASP verifying keys on ledger start-up.
  ([\#2272](https://github.com/anoma/namada/pull/2272))
- Now join-network will try to look for non validator wallet in more places.
  ([\#2273](https://github.com/anoma/namada/pull/2273))

## v0.28.0

Namada 0.28.0 is a minor release that improves the genesis setup to allow signing with hardware wallet and contains various improvements including validator liveness jailing, accounts simplifications, bug fixes, stability improvements and more.

### BUG FIXES

- Fix the start block height of the first epoch.
  ([\#1993](https://github.com/anoma/namada/pull/1993))
- Fix Ethereum event validation/state updates when more than one validator is
  running the chain ([\#2035](https://github.com/anoma/namada/pull/2035))
- Fix possible underflow in MASP rewards calculation.
  ([\#2230](https://github.com/anoma/namada/pull/2230))

### IMPROVEMENTS

Allow  the ethereum oracle to be activated / deactivated via config 
updates sent from ledger. This allows governance to shut down the 
ledger without restarts. Otherwise, disconnecting from Ethereum will
result in the ledger crashing.
([\#1764](https://github.com/anoma/namada/pull/1764))
- Prune merkle tree of bridge pool
  ([\#2110](https://github.com/anoma/namada/issues/2110))
- Revert the chain ID format by upgrading ibc-rs to 0.48.1
  ([\#2153](https://github.com/anoma/namada/issues/2153))
- Changed pre-genesis established addresses to be derived from their data.
  Improved signing of pre-genesis transactions to use the same format as
  regular transactions. Genesis token balances now can be directly assigned to
  established addresses. ([\#2186](https://github.com/anoma/namada/pull/2186))
- Combined the user and the validator VP into one.
  ([\#2202](https://github.com/anoma/namada/pull/2202))
- Charge gas for network usage.
  ([\#2205](https://github.com/anoma/namada/pull/2205))
- A new `tx_become_validator` replaces `tx_init_validator`. This tx doesn't
  initialize a new account and instead it modifies an existing established
  address to become a validator. This currently requires that there are no
  delegations on the source account before it can become a validator (if there
  are some, they have to be unbonded, but they don't have to be withdrawn).
  A new client command `become-validator` is added that requires an `--address`.
  The client command `init-validator` is kept for convenience and updated to
  send `tx_init_account` tx before `tx_become_validator`.
  ([\#2208](https://github.com/anoma/namada/pull/2208))
- Increase hardware wallet support in the CLI
  ([\#2209](https://github.com/anoma/namada/pull/2209))
- Handle errors on loading WASMs from file-system compilation cache.
  ([\#2215](https://github.com/anoma/namada/pull/2215))
- Implement a CLI query for available rewards from a bond,
  and improve the bond amount for rewards computation
  ([\#2217](https://github.com/anoma/namada/pull/2217))
- Fix bug in client to allow for unjailing a validator
  that was jailed for missing liveness requirements
  ([\#2246](https://github.com/anoma/namada/pull/2246))

### MISCELLANEOUS

- Upgraded borsh dependency to v1.2.0.
  ([\#2233](https://github.com/anoma/namada/pull/2233))

### SDK

- Removed uses of lifetimes in the SDKs Namada trait and implementation
  ([\#2225](https://github.com/anoma/namada/pull/2225))
- Added Send trait support to the SDK to allow its use in more multithreaded
  contexts. ([\#2235](https://github.com/anoma/namada/pull/2235))

## v0.27.0

Namada 0.27.0 is a minor release that incorporates the remaining essential proof-of-stake features, updates the MASP and transaction functionality, and provides some additions to the SDK.

### BUG FIXES

- Fix a feature flag to compile namada_sdk
  ([\#2164](https://github.com/anoma/namada/issues/2164))
- Fix to get the proof even if no height is specified
  ([\#2166](https://github.com/anoma/namada/issues/2166))
- Fix ABCI queries at the last committed height
  ([\#2184](https://github.com/anoma/namada/pull/2184))

### FEATURES

- Tx that allows a validator to change its consensus key
  ([\#2137](https://github.com/anoma/namada/pull/2137))

### IMPROVEMENTS

- Moved the masp vp to native.
  ([\#2051](https://github.com/anoma/namada/pull/2051))
- Tighten security around potential P2P issues
  ([\#2131](https://github.com/anoma/namada/pull/2131))
- Print more context from eyre error types.
  ([\#2132](https://github.com/anoma/namada/pull/2132))
- Require to verify ownership of all validator keys when initialized on-chain.
  ([\#2163](https://github.com/anoma/namada/pull/2163))
- Improve the validator VP to ensure that only the validator themself
  can execute transactions that manipulate its own validator data
  ([\#2169](https://github.com/anoma/namada/pull/2169))
- Various improvements to the PoS code, including adding a panic on a slashing
  failure, some more checked arithmetics, aesthetic code cleanup, and fixing a
  bug in is_delegator. ([\#2178](https://github.com/anoma/namada/pull/2178))
- Added type tags to transactions to enable hardware wallets
  to fully decode transactions even after minor Namada updates.
  ([\#2182](https://github.com/anoma/namada/pull/2182))
- Save MASP conversion state to the state storage instead of the diffs
  ([\#2189](https://github.com/anoma/namada/issues/2189))

### MISCELLANEOUS

- Removed catching of panics from PoS VP.
  ([\#2145](https://github.com/anoma/namada/pull/2145))

### SDK

- Masp as internal address. Updated `aux_signing_data`
  to return no key and 0 threshold if owner is masp.
  ([\#2051](https://github.com/anoma/namada/pull/2051))
- A high level function new_redelegate is added to the sdk to allow developers
  to make and submit redelegation functions from the minimum number of arguments
  required ([\#2140](https://github.com/anoma/namada/pull/2140))

## v0.26.0

Namada 0.26.0 is a minor release on the way to mainnet with updates to PoS and governance as well as its upstream dependencies.

### BUG FIXES

- Fix Windows build by disabling RocksDB jemalloc feature.
  ([\#2100](https://github.com/anoma/namada/pull/2100))
- Fix balance query not to return duplicate results
  ([\#2125](https://github.com/anoma/namada/issues/2125))
- Fixed bugs in the governance VP and in the PGF inflation mechanism.
  ([\#2133](https://github.com/anoma/namada/pull/2133))
- Added handling of ABCI Info requests load-shedding and removed load-shedding
  from Mempool requests. ([\#2152](https://github.com/anoma/namada/pull/2152))

### FEATURES

- Implements a claim-based rewards system for PoS inflation.
  ([\#1992](https://github.com/anoma/namada/pull/1992))
- Store validator metadata on-chain
  ([\#2045](https://github.com/anoma/namada/pull/2045))
- Add transactions to deactivate and reactivate a validator
  ([\#2082](https://github.com/anoma/namada/pull/2082))
- Added Ledger support to the CLI client.
  ([\#2118](https://github.com/anoma/namada/pull/2118))
- Added the option to abstain from voting a governance proposal.
  ([\#2128](https://github.com/anoma/namada/pull/2128))

### IMPROVEMENTS

- Improved replay protection for invalid transactions.
  ([\#1905](https://github.com/anoma/namada/pull/1905))
- store only essential merkle tree snapshots
  ([\#2043](https://github.com/anoma/namada/issues/2043))
- Replace strings with a specialized IBC token hash type in addresses
  ([\#2046](https://github.com/anoma/namada/pull/2046))
- Switch to a more compact representation in Namada's transparent
  addresses, and change all bech32m HRPs to their mainnet equivalent
  ([\#2060](https://github.com/anoma/namada/pull/2060))
- refactoring IBC and remove IBC token denomination
  ([\#2062](https://github.com/anoma/namada/issues/2062))
- Upgraded to upstream ibc-rs and tendermint-rs crates.
  ([\#2084](https://github.com/anoma/namada/pull/2084))
- Updated the gas costs. Introduced a local validator configuration
  parameter to set the accepted tokens and amounts for fees.
  ([\#2091](https://github.com/anoma/namada/pull/2091))
- Moved the inner transaction replay check at execution time.
  ([\#2104](https://github.com/anoma/namada/pull/2104))
- Removed "abcipp" and "abciplus" features and "abcipp"-only code.
  ([\#2112](https://github.com/anoma/namada/pull/2112))
- Removed the DKG implementation with its ferveo dependency.
  ([\#2115](https://github.com/anoma/namada/pull/2115))
- Upgraded to upstream tower-abci version.
  ([\#2141](https://github.com/anoma/namada/pull/2141))

### SDK

- Updated the `LedgerProposalVote` display method to account for the new
  `Abstain` vote variant. ([\#2128](https://github.com/anoma/namada/pull/2128))

## v0.25.0

This release includes only the new genesis flow.

### FEATURES

- Added bech32m string encoding for `common::PublicKey` and `DkgPublicKey`.
  ([\#2088](https://github.com/anoma/namada/pull/2088))
- Added `--pre-genesis` argument to the wallet commands to allow to generate
  keys, implicit addresses and shielded keys without having a chain setup. If
  no chain is setup yet (i.e. there's no base-dir or it's empty), the wallet
  defaults to use the pre-genesis wallet even without the `--pre-genesis`
  flag. The pre-genesis wallet is located inside base-dir in
  `pre-genesis/wallet.toml`.
  ([\#2088](https://github.com/anoma/namada/pull/2088))
- Reworked the genesis templates, setup and related utils commands.
  ([\#2088](https://github.com/anoma/namada/pull/2088))

## v0.24.1

Namada 0.24.1 is a patch release addressing ledger startup problems with wasm artifacts and several other minor fixes.

### BUG FIXES

- Fix Windows build by disabling RocksDB jemalloc feature.
  ([\#2047](https://github.com/anoma/namada/pull/2047))

### IMPROVEMENTS

- Define the wasm download endpoint via environment variable.
  ([\#2064](https://github.com/anoma/namada/pull/2064))

## v0.24.0

Namada 0.24.0 is a minor release that introduces an SDK crate, PoS redelegation, various updates and fixes for IBC, PoS, governance, ETH bridge and the ledger.

### BUG FIXES

- Reintroduced a dummy field in order to achieve compatibility with hardware
  wallet. ([\#1949](https://github.com/anoma/namada/pull/1949))
- Fix broadcasting logic for protocol txs when a node operating the network is a
  validator ([\#1964](https://github.com/anoma/namada/pull/1964))
- Avoid redundant storage deletions in lazy collections that would incur
  extra gas cause and appear in transaction result as changed keys even if not
  changed occurred. This may have caused PoS transactions to run out of gas.
  ([\#1984](https://github.com/anoma/namada/pull/1984))
- Update ibc-rs with the fix for ibc-rs/#911
  ([\#1989](https://github.com/anoma/namada/issues/1989))
- Fixed the pgf stewards reward to be constant regardless of the number of
  stewards. ([\#1999](https://github.com/anoma/namada/pull/1999))

### IMPROVEMENTS

- Reworked the signature of inner transactions to improve safety and fix replay
  protection. ([\#1867](https://github.com/anoma/namada/pull/1867))
- Updated the generation of hardware wallet test vectors to cover current
  codebase ([\#1888](https://github.com/anoma/namada/pull/1888))
- IBC transfer to a payment address
  ([\#1917](https://github.com/anoma/namada/issues/1917))
- Migrate to upstream borsh ([\#1930](https://github.com/anoma/namada/pull/1930))
- Improve the Epoched data structure's bookkeeping of past
  epochs, now parameterizable by PoS and governance params.
  ([\#1943](https://github.com/anoma/namada/pull/1943))
- New implementation and parameters for purging old epochs for Epoched validator
  data in storage. ([\#1944](https://github.com/anoma/namada/pull/1944))
- Query also IBC token balances
  ([\#1946](https://github.com/anoma/namada/issues/1946))
- Increased resoultion of gas accounting for signature verification.
  ([\#1954](https://github.com/anoma/namada/pull/1954))
- Refactor benchmarks to avoid enabling `"testing`" and `"dev"`` features by 
  default in the workspace.
  ([\#1955](https://github.com/anoma/namada/pull/1955))
- Add missing checks for the commission rate change tx and code clean-up
  ([\#1973](https://github.com/anoma/namada/pull/1973))
- Reduced the storage consumption of replay protection.
  ([\#1977](https://github.com/anoma/namada/pull/1977))
- Persist the results of governance proposals in storage to allow recovering old
  results. ([\#1979](https://github.com/anoma/namada/pull/1979))
- MASP rewards are now distributed in the manner dictated by the PD-controller
  ([\#1985](https://github.com/anoma/namada/pull/1985))
- Wait for a node to sync before broadcasting protocol txs
  ([\#2001](https://github.com/anoma/namada/pull/2001))
- Sign transactions originating from the Namada relayer that are sent to
  Ethereum ([\#2012](https://github.com/anoma/namada/pull/2012))

### MISCELLANEOUS

- Switched from using `libsecp256k1` to `k256` crate.
  ([\#1958](https://github.com/anoma/namada/pull/1958))
- Tag `ed25519` keys with `ZeroizeOnDrop`
  ([\#1958](https://github.com/anoma/namada/pull/1958))

### SDK

- Phase out Halt abstractions
  ([\#1953](https://github.com/anoma/namada/pull/1953))
- Validate Bridge pool transfers before submitting them to the network
  ([\#1957](https://github.com/anoma/namada/pull/1957))
- Improved the usability of the SDK and moved it to separate crate.
  ([\#1963](https://github.com/anoma/namada/pull/1963))
- Now re-exporting crates that will commonly be used with the SDK.
  ([\#2033](https://github.com/anoma/namada/pull/2033))

### TESTING

- Mock ledger services in integration tests
  ([\#1976](https://github.com/anoma/namada/pull/1976))

## v0.23.1

Namada 0.23.1 is a patch release fixing a potential ledger crash on the pgf module.

### BUG FIXES

- Fixed a bug that would cause the ledger to crash on a failed PGF payment.
  ([\#1991](https://github.com/anoma/namada/pull/1991))

## v0.23.0

Namada is a minor release that improves the ethereum bridge, the IBC mechanism, and fixes some general protocol bugs.

### BUG FIXES

- Fixed a bug in the parallel gas accounting of validity predicates.
  ([\#1835](https://github.com/anoma/namada/pull/1835))
- Removed gas and fees related panics from the sdk.
  ([\#1878](https://github.com/anoma/namada/pull/1878))
- Fix lower bound in client proposal vote check
  ([\#1887](https://github.com/anoma/namada/pull/1887))
- Respect force option for proposal vote transaction
  ([\#1889](https://github.com/anoma/namada/pull/1889))
- Never overwrite recent Bridge pool proofs in storage
  ([\#1893](https://github.com/anoma/namada/pull/1893))
- Keep a record of the first block heights of every epoch in the chain's history
  instead of trimming to only keep this data for a certain number of epochs in
  the past. ([\#1898](https://github.com/anoma/namada/pull/1898))
- Added wasm validation in `init_chain` and in client utils.
  ([\#1902](https://github.com/anoma/namada/pull/1902))
- Implement IBC tx execution via a native host function to workaround Mac M1/2
  WASM compilation issues. ([\#1904](https://github.com/anoma/namada/pull/1904))

### FEATURES

- Replaced standard IO in SDK and client code with a trait that allows custom
  handling. ([\#1746](https://github.com/anoma/namada/pull/1746))

### IMPROVEMENTS

- Rework voting on Ethereum tallies across epoch boundaries
  ([\#1865](https://github.com/anoma/namada/pull/1865))
- Move all functions considered to be apart of the SDK to the SDK
  folder. ([#1868](https://github.com/anoma/namada/pull/1868))
- Remove pay-fee-with-pow feature and faucet vp.
  ([\#1873](https://github.com/anoma/namada/pull/1873))
- Removed redundant `WasmPayload` enum in favor of `Commitment`.
  ([\#1874](https://github.com/anoma/namada/pull/1874))
- Added a section in CONTRIBUTING.md to outline how to document SDK
  changes ([#1876](https://github.com/anoma/namada/pull/1876))
- Refactored retrieval of `Transaction` object for fee unshielding.
  ([\#1877](https://github.com/anoma/namada/pull/1877))
- Renamed `gas_cost` to `minimum_gas_price` in the genesis file.
  ([\#1882](https://github.com/anoma/namada/pull/1882))
- Enable hardware wallets to participate in nondegenerate multisignature
  transactions. ([\#1884](https://github.com/anoma/namada/pull/1884))
- Added support for validators' hostnames in configuration.
  ([\#1886](https://github.com/anoma/namada/pull/1886))
- Allow Bridge pool transfers to pay zero gas fees
  ([\#1892](https://github.com/anoma/namada/pull/1892))
- Forced the `async_trait`s' futures in the SDK to be `Send`.
  ([\#1894](https://github.com/anoma/namada/pull/1894))
- Retransmit timed out Ethereum events in case they have accumulated >1/3 voting
  power ([\#1899](https://github.com/anoma/namada/pull/1899))
- Move the IBC native VP to a different module
  ([\#1927](https://github.com/anoma/namada/pull/1927))

### MISCELLANEOUS

- Migrate to the new Ethereum contracts
  ([\#1885](https://github.com/anoma/namada/pull/1885))

### SDK

- The shared-utils topic ([#1868](https://github.com/anoma/namada/pull/1868)) moves the following:
  + _Modules_
    | From                                    | To                                   |
    |-----------------------------------------|--------------------------------------|
    | namada::ledger::tx                      | namada::sdk::tx                      |
    | namada::ledger::rpc                     | namada::sdk::rpc                     |
    | namada::ledger::signing                 | namada::sdk::signing                 |
    | namada::ledger::masp                    | namada::sdk::masp                    |
    | namada::ledger::args                    | namada::sdk::args                    |
    | namada::ledger::wallet::alias           | namada::sdk::wallet::alias           |
    | namada::ledger::wallet::derivation_path | namada::sdk::wallet::derivation_path |
    | namada::ledger::wallet::keys            | namada::sdk::wallet::keys            |
    | namada::ledger::wallet::pre_genesis     | namada::sdk::wallet::pre_genesis     |
    | namada::ledger::wallet::store           | namada::sdk::wallet::store           |
    | namada::types::error                    | namada::sdk::error                   |

  + _Types_

    | From                            | To                           |
    |---------------------------------|------------------------------|
    | namada::ledger::queires::Client | namada::sdk::queires::Client |
- Added two new variants to the `TxError` enum, `BalanceToLowForFees` and
  `FeeUnshieldingError`, representing possible failures in transactions' fees.
  ([\#1878](https://github.com/anoma/namada/pull/1878))
- Added the `Send` bound to the `Client` and `ShieldedUtils` `async_trait`s'.
  This allows the SDK to be used in environments which are both asynchronous and
  multithread. ([\#1894](https://github.com/anoma/namada/pull/1894))

### TESTING

- Updated benchmarks and added tests to ensure they're working.
  ([\#1907](https://github.com/anoma/namada/pull/1907))

## v0.22.0

Namada 0.22.0 is a minor release introducing a redefined PGF mechanism, a proper gas module, and major 
improvements to the sdk and ethereum bridge.

### BUG FIXES

- Fix IBC amount handling ([\#1744](https://github.com/anoma/namada/issues/1744))
- Fix wasm pointer misalignment issues on Apple silicon devices.
  ([\#1778](https://github.com/anoma/namada/pull/1778))
- Fix the decoding of events observed by the Ethereum oracle
  ([\#1852](https://github.com/anoma/namada/pull/1852))
- Trigger the NUT VP when NUTs are moved between accounts during wasm
  transaction execution ([\#1854](https://github.com/anoma/namada/pull/1854))
- Fix the Ethereum Bridge VP
  ([\#1855](https://github.com/anoma/namada/pull/1855))
- Miscellaneous Ethereum smart contract nonce fixes
  ([\#1856](https://github.com/anoma/namada/pull/1856))
- Log proper duped validator votes on Ethereum tallies
  ([\#1860](https://github.com/anoma/namada/pull/1860))

### FEATURES

- Implement Ethereum token whitelist.
  ([\#1290](https://github.com/anoma/namada/issues/1290))
- Implemented the runtime gas and fee system.
  ([\#1327](https://github.com/anoma/namada/pull/1327))
- Control the flow of NAM over the Ethereum bridge
  ([\#1781](https://github.com/anoma/namada/pull/1781))
- Update ethbridge-rs to v0.22.0
  ([\#1789](https://github.com/anoma/namada/pull/1789))
- Allow Bridge pool transfer fees to be paid in arbitrary token types (except
  NUTs) ([\#1795](https://github.com/anoma/namada/pull/1795))

### IMPROVEMENTS

- Adds the possibility to dump the state of the db at a custom height.
  ([\#1468](https://github.com/anoma/namada/pull/1468))
- Added various fee types to the output of the Bridge pool recommendations RPC
  ([\#1811](https://github.com/anoma/namada/pull/1811))
- Ensure that Namada (shared) crate can be built for WASM target.
  ([\#1828](https://github.com/anoma/namada/pull/1828))
- Upgraded the MASP crate commit used by Namada to the latest version.
  ([\#1842](https://github.com/anoma/namada/pull/1842))
- Add the Bridge pool as a default wallet address
  ([\#1848](https://github.com/anoma/namada/pull/1848))
- Call `Message::parse` directly
  ([\#1849](https://github.com/anoma/namada/pull/1849))
- Parse Eth addresses from the CLI
  ([\#1850](https://github.com/anoma/namada/pull/1850))
- Split Bridge pool transfer hashes on all whitespace toks
  ([\#1851](https://github.com/anoma/namada/pull/1851))
- Denominate non-whitelisted NUT amounts
  ([\#1853](https://github.com/anoma/namada/pull/1853))
- Removed replay protection storage keys from the merkle tree.
  ([\#1863](https://github.com/anoma/namada/pull/1863))

## v0.21.1

Namada 0.21.0 is a patch release addressing some minor changes to the PGF and IBC components.

### BUG FIXES

- Introduce a new genesis section to control PGF storage at chain start.
  ([\#1816](https://github.com/anoma/namada/pull/1816))

### FEATURES

- Support the memo field of IBC transfer
  ([\#1635](https://github.com/anoma/namada/issues/1635))

## v0.21.0

Namada 0.21.0 is a minor release introducing a first version of the PGF mechanism, addressing several 
improvements to the PoS and Governance system and some changes to the ledger stability.

### BUG FIXES

- Fixes buggy Display for the Dec type when the number is some multiple of 10
  ([\#1774](https://github.com/anoma/namada/pull/1774))
- Downgraded sysinfo back to v0.27.8 with a working available memory report on
  Mac M1. ([\#1775](https://github.com/anoma/namada/pull/1775))
- Fixes buggy error handling in pos unjail_validator. Now properly enforces that
  if an unjail tx is submitted when the validator state is something other than
  Jailed in any of the current or future epochs, the tx will error out and fail.
  ([\#1793](https://github.com/anoma/namada/pull/1793))
- Fix available_memory size
  ([\#1801](https://github.com/anoma/namada/issues/1801))

### FEATURES

- Introduce multisignature accounts and transaction format. It is now possible
  to supply multiple public keys when creating a new account/validator and
  specify the minimum number of signatures required to authorize a transaction.
  ([\#1765](https://github.com/anoma/namada/pull/1765))
- Introduce a simplified version of Public Good Fundings.
  ([\#1803](https://github.com/anoma/namada/pull/1803))

### TESTING

- Added pre-built MASP proofs for integration tests.
  ([\#1768](https://github.com/anoma/namada/pull/1768))

## v0.20.1

Namada 0.20.1 is a patch release addressing a bug in the inflation mechanism and minor ledger improvements.

### BUG FIXES

- Ensure that each crate in the workspace can be built with default features.
  ([\#1712](https://github.com/anoma/namada/pull/1712))
- Fixed transparent balance query when only an owner address is specified without
  an explicit token. ([\#1751](https://github.com/anoma/namada/pull/1751))
- Fixes how PoS inflation is calculated.
  ([\#1756](https://github.com/anoma/namada/pull/1756))
- Fixes the ordering for I256 type.
  ([\#1763](https://github.com/anoma/namada/pull/1763))

### IMPROVEMENTS

- Removed the associated type for an address from `trait NativeVp`.
  ([\#1725](https://github.com/anoma/namada/pull/1725))

## v0.20.0

Namada 0.20.0 is a minor releasing addressing several improvements to the PoS system and the ledger 
stability.

### BUG FIXES

- Fix genesis `faucet_withdrawal_limit` parser to respect tokens' denomination.
  ([\#1667](https://github.com/anoma/namada/pull/1667))
- PoS: ensure that the size of genesis validator set
  is limited by the `max_validator_slots` parameter.
  ([\#1686](https://github.com/anoma/namada/pull/1686))
- Fix inconsistency state before commit
  ([\#1709](https://github.com/anoma/namada/issues/1709))
- PoS: Fixed an epoch boundary issue in which a validator who's being slashed
  on a start of a new epoch is disregarded during processing of block votes.
  ([\#1729](https://github.com/anoma/namada/pull/1729))

### IMPROVEMENTS

- PoS: purge validator sets for old epochs from the storage; store total
  validator stake ([\#1129](https://github.com/anoma/namada/issues/1129))
- Added a reusable token balance query method.
  ([\#1173](https://github.com/anoma/namada/pull/1173))
- Replaced file-lock with fd-lock dependency to support Windows build.
  ([\#1605](https://github.com/anoma/namada/pull/1605))
- Added a command to wait for the next epoch: `client utils epoch-sleep`.
  ([\#1621](https://github.com/anoma/namada/pull/1621))
- Added a client query for `validator-state` and improved the slashes query to
  show more info. ([\#1656](https://github.com/anoma/namada/pull/1656))
- Removed associated type on `masp::ShieldedUtils`. This type was an
  attempt to reduce the number of generic parameters needed when interacting
  with MASP but resulted in making code re-use extremely difficult.
  ([\#1670](https://github.com/anoma/namada/pull/1670))
- Removed `impl From<u64> for EthBridgeVotingPower` and replaced it with a
  `TryFrom`. ([\#1692](https://github.com/anoma/namada/pull/1692))
- Updated sysinfo dependency.
  ([\#1695](https://github.com/anoma/namada/pull/1695))
- Refactored storage code to only use an immutable reference when reading and
  writing to a batch. ([\#1717](https://github.com/anoma/namada/pull/1717))

### MISCELLANEOUS

- Replaced token sub-prefix with a multitoken address and native VP for IBC and
  ETH bridge. ([\#1693](https://github.com/anoma/namada/pull/1693))
- PoS: Keep the data for last two epochs by default.
  ([\#1733](https://github.com/anoma/namada/pull/1733))
- Refactored CLI into libraries for future re-use in integration tests and
  to enable generic IO. ([\#1738](https://github.com/anoma/namada/pull/1738))

### TESTING

- Added integration testing infrastructure for node, client and
  the wallet and replaced MASP E2E tests with integration tests.
  ([\#1714](https://github.com/anoma/namada/pull/1714))

## v0.19.0

Namada 0.19.0 is a minor releasing addressing the integration with the namada trustless ethereum bridge.

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

- Fixed the PrefixIter order of iteration in the write-
  log to always match the iteration order in the storage.
  ([#1141](https://github.com/anoma/namada/pull/1141))
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

