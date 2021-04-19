# Accounts

[Tracking Issue](https://github.com/heliaxdev/rd-pm/issues/25)

---

There's only a single account type. Each account is associated with:
- a unique [address](#addresses)
- a [validity predicate](./vp.md)
- [dynamic storage sub-space](#dynamic-storage-sub-space)

## Addresses

There are two types of address: transparent and shielded. 

The transparent addresses are similar to domain names and the ones used in e.g. [ENS as specified in EIP-137](https://eips.ethereum.org/EIPS/eip-137) and [account IDs in Near protocol](https://nomicon.io/DataStructures/Account.html). These are the addresses of accounts associated with dynamic storage sub-spaces, where the address of the account is the prefix key segment of its sub-space.

The shielded addresses are used for private transactions and they are not directly associated with storage sub-spaces.

### Transparent addresses

A transparent address is a human-readable string very similar to a domain name, containing only alpha-numeric ASCII characters, hyphen (`-`) and full stop (`.`) as a separator between the "labels" of the address. The letter case is not significant and any upper case letters are converted to lower case. The last label of an address is said to be the top-level name and each predecessor segment is the sub-name of its successor.

The length of an address must be at least 3 characters. For compatibility with a legacy DNS TXT record, we'll use syntax as defined in [RFC-1034 - section 3.5 DNS preferred name syntax](https://www.ietf.org/rfc/rfc1034.txt). That is, the upper limit is 255 characters and 63 for each label in an address (which should be sufficient anyway); and the label must not begin or end with hyphen (`-`) and must not begin with a digit.

These addresses can be chosen by users who wish to [initialize a new account](#initializing-a-new-account), following these rules:

- a new address must be initialized on-chain
  - each sub-label must be authorized by the predecessor level address (e.g. initializing address `free.eth` must be authorized by `eth`, or `gives.free.eth` by `free.eth`, etc.) 
  - note that besides the address creation, each address level is considered to be a distinct address with its own dynamic storage sub-space and validity predicate.
- the top-level names under certain length (to be specified) cannot be initialized directly, they may be [auctioned like in ENS registrar as described in EIP-162](https://eips.ethereum.org/EIPS/eip-162).
  - some top-level names may be reserved

For convenience, the `anoma` top-level address is initially setup to allow initialization of any previously unused second-level address, e.g. `bob.anoma` (we may want to revise this before launch to e.g. action the short ones, like with top-level names to make the process fairer).

Like in ENS, the addresses are stored on chain by their hash, encoded with [bech32m](https://github.com/bitcoin/bips/blob/master/bip-0350.mediawiki) ([not yet adopted in Zcash](https://github.com/zcash/zips/issues/484)), which is an improved version of [bech32](https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki). Likewise, this is for two reasons:
- help preserve privacy of addresses that were not revealed publicly and to prevent trivial enumeration of registered names (of course, you can still try to enumerate by hashes)
- using fixed-length string in the ledger simplifies gas accounting

The human-readable prefix (as specified for [bech32](https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki#specification)) in the address encoding is:
- `"a"` for Anoma live network
- `"atest"` for test network

### Shielded addresses

Similar to [Zcash Sapling protocol payment addresses and keys (section 3.1)](https://raw.githubusercontent.com/zcash/zips/master/protocol/protocol.pdf), users can generate spending keys for private payments. A shielded payment address, incoming viewing key and full viewing key are derived from a spending key. In a private payment, a shielded payment address is hashed with a diversifier into a diversified transmission key. When a different diversifier function is chosen for different transactions, it prevents the transmission key from being matched across the transactions.

The encoding of the shielded addresses, spending and viewing keys is not yet decided, but for consistency we'll probably use a the same schema with different prefixes for anything that can use an identifier.

- TODO consider using a schema similar to the [unified addresses proposed in Zcash](https://github.com/zcash/zips/issues/482), that are designed to unify the payment addresses across different versions by encoding a typecode and the length of the payment address together with it. This may be especially useful for the protocol upgrade system and fractal scaling system.

## Dynamic storage sub-space

Each account can have an associated dynamic account state in the storage. This
state may be comprised of keys of the built-in supported types and values of arbitrary user bytes.

The dynamic storage sub-space could be a unix filesystem-like tree under the
account's address key-space with `read, write, delete, has_key, iter_prefix`
(and maybe a few other convenience functions for hash-maps, hash-sets, optional values, etc.) functions parameterized with the the account's address.

In addition, the storage sub-space would provide:
- a public type/trait for storage keys and key segments:
  - this should allow to turn types to storage key segments, key segments back to types
  - combine key segments into keys
  - can be extended with custom types in the code in a transaction
- a public type/trait for storage values:
  - values need to implement encoding traits, e.g. `BorshSerialize, BorshDeserialize`
    - this allows composition of types as specified for [Borsh](https://borsh.io)
    - the Merkle tree hashing function should hash values from the encoded bytes of this trait (the encoded value may be cached, because we update the Merkle tree in-memory before we commit the finalized block to the DB)
- functions to get the size of a key and an encoded value (for storage fees)
- the updates to account storage should be immediately visible to the transaction that performed the updates
  - validity predicate modifications have to be handled a little differently -
    the old validity predicate should be run to check that the new validity
    predicate (and other state changes included in the transaction) is valid

## Initializing a new account

A new account can be initialized on-chain with a transaction:

- anything be written into its storage (initial parameter)
- a validity predicate has to be provided (we can have a default out-of-band)
- at minimum, accounts need to be enumerated on chain, this could be done with an address or a counter

A newly created account should be validated by all the VPs triggered by the transaction, i.e. it should be included in the set of changed keys passed to each VP. If the VPs are not interested in the newly created account, they can choose to ignore it.
