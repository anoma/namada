# k-of-n multisignature

The k-of-n multisignature validity predicate authorises transactions on the basis of k out of n parties approving them. This document targets the encrypted wasm transactions: at the moment there's no support for multisignature on wrapper or protocol transactions.

## Protocol

Namada transactions get signed before being delivered to the network. This signature is then checked by the VPs to determine the validity of the transaction. To support multisignature we need to extend the current `SignedTxData` struct to the following:

```rust
pub enum Signature {
    Sig(common::Signature),
    MultiSig(Vec<common::Signature>)
}

pub struct SignedTxData {
    /// The original tx data bytes, if any
    pub data: Option<Vec<u8>>,
    /// The signature is produced on the tx data concatenated with the tx code
    /// and the timestamp.
    pub sig: Signature,
}
```

This struct will now hold either a signature or multiple signatures over the data carried by the transaction. The different enum variants allow for a quick check of the correct signature type at validation time.

## VPs

To support multisig we provide a new `vp_multisig` wasm validity predicate that can be used instead of the usual `vp_user` for `implicit addresses` (see [spec](./default-account.md)). This new vp will be generic, it will allow for arbitrary actions on the account as long as the signatures are valid.

Moreover, `established` and `internal` addresses may want a multi-signature scheme on top of their validation process. Among the internal ones, `PGF` will require multisignature for its council (see the [relative](../economics/public-goods-funding.md) spec).

To support the validity checks, the VP will need to access two types of information:

1. The multisig threshold
2. A list of valid signers' public keys

This data defines the requirements of a valid transaction operating on the multisignature address and it will be written in storage when the account is first created:

```
/\$Address/multisig/threshold/: u8
/\$Address/multisig/pubkeys/: Vec<PublicKey>
```

To verify the correctness of the signatures, these VPs will proceed with a four-steps verification process:

1. Check that the type of the signature is `MultiSig`
2. Check to have enough **unique** signatures for the given threshold
3. Validate the signatures
4. Check to have enough **valid** signatures for the given threshold

Steps 1 and 2 allow to short-circuit the validation process and avoid unnecessary processing and storage access. The signatures will be validated against the list of predefined public keys: a signature will be rejected if it's not valid for any of these public keys. Step 4 will halt as soon as it retrieves enough valid signatures to match the threshold, meaning that the remaining signatures will not be verified.

## Transaction construction

To craft a multisigned transaction, the involved parties will need to coordinate. More specifically, the transaction will be constructed by one entity which will then distribute it to the signers and collect their signatures: note that the constructing party doesn't necessarily need to be one of the signers. Finally, these signatures will be inserted in the `SignedTxData` struct so that they can be encrypted, wrapped and submitted to the network.

Namada does not provide a layer to support this process, so the involved parties will need to rely on an external communication mechanism.
