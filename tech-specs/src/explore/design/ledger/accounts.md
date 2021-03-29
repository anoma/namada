# Accounts

tracking issue <https://github.com/heliaxdev/rd-pm/issues/25>

TODO Detail the account types, their data, addresses, etc.

## Dynamic storage sub-space

Each account can have associated dynamic account state in the storage. This state may be comprised of key/value pairs of the built-in supported types and values may also be arbitrary user bytes.

The dynamic storage sub-space could be unix filesystem-like tree under the account's address key-space with e.g.: `read, write, delete, has_key, iter_prefix` (and maybe a few other functions for hash-maps, hash-sets, optional values, etc. for convenience) functions parameterized with the the account's address.

In addition, the storage sub-space would provide:
- a public type/trait for storage keys and key segments:
  - this should allow to turn types to storage key segments, key segments back to types
  - combine key segments into keys
  - can be extended with custom types in transactions' code
- a public type/trait for storage values:
  - values need to implement encoding traits, e.g. `BorshSerialize, BorshDeserialize`
    - this allows composition of types as specified for [Borsh](https://borsh.io)
    - the Merkle tree hashing function should hash values from the encoded bytes of this trait (the encoded value may be cached, because we update the Merkle tree in-memory before we commit the finalized block to the DB)
- functions to get the size of a key and an encoded value (for storage fees)
- the updates to account storage should be immediately visible to the transaction that performed the updates
  - validity predicate modifications have to be handled a little differently - the old validity predicate should be run to check that the new validity predicate (and other state changes included in the transaction) are valid

## Initializing a new account

A new account can be initialized on-chain with a transaction:

- anything be written into its storage (initial parameter)
- a validity predicate has to be provided (we can have a default out-of-band)
- at minimum, accounts need to be enumerated on chain, this could be done with an address or a counter
