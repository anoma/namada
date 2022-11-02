## Asset name schema

MASP notes carry balances that are some positive integer amount of an
asset type. Per both the MASP specification and the implementation, the
asset *identifier* is an 32-byte [Blake2s hash](https://www.blake2.net/) of an arbitrary asset
*name* string, although the full 32-byte space is not used because the
identifier must itself hash to an elliptic curve point (currently
guaranteed by incrementing a nonce until the hash is a curve point). The
final curve point is the asset *type* proper, used in computations.

The following is a schema for the arbitrary asset name string intended
to support various uses - currently fungible tokens and NFTs, but possibly
others in future.

The asset name string is built up from a number of segments, joined by a
separator. We use `/` as the separator.

Segments may be one of the following:

- **Controlling address** segment: a Namada address which controls the
  asset. For example, this is the fungible token address for a fungible
  token. This segment must be present, and must be first; it should in
  theory be an error to transparently transact in assets of this type
  without invoking the controlling address's VP. This should be achieved
  automatically by all transparent changes involving storage keys under
  the controlling address.

- **Epoch** segment: An integer greater than zero, representing an epoch
  associated with an asset type. Mainly for use by the incentive
  circuit. This segment must be second if present. (should it be
  required? could be 0 if the asset is unepoched) (should it be first so
  we can exactly reuse storage keys?) This must be less than or equal to
  the current epoch.

- **Address** segment: An ancillary address somehow associated with the
  asset. This address probably should have its VP invoked, and is
  probably in the transparent balance storage key.

- **ID** segment: A nonnegative (?) integer identifying something, i.e.,
  a NFT id. (should probably not be a u64 exactly - for instance, I
  think ERC721 NFTs are u256)

- **Text** segment: A piece of text, normatively but not necessarily
  short (50 characters or less), identifying something. For
  compatibility with non-numeric storage keys used in transparent assets
  generally; an example might be a ticker symbol for a specific
  sub-asset. The valid character set is the same as for storage keys.

For example, suppose there is a virtual stock certificate asset,
incentivized (somehow), at transparent address `addr123`, which uses
storage keys like `addr123/[owner address]/[ticker symbol]/[id]`. The
asset name segments would be:

- Controlling address: just `addr123`
- Epoch: the epoch when the note was created
- Owner address: an address segment
- Ticker symbol: a text segment
- ID: an ID segment

This could be serialized to, e.g., `addr123/addr456/tSPY/i12345`.
