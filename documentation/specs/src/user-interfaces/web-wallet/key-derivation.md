## Key Derivation (transparent addresses)

Given a master seed (a 12 or 24 word `bip39` mnemonic), the user should be able to derive additional accounts deterministically.

The wallet currently implements functionality to derive `bip32` addresses following `bip44` paths for [slip-0044](https://github.com/satoshilabs/slips/blob/master/slip-0044.md) registered coin types, using hardened addresses.

The bulk of this funcionality resides in `namada-apps/namada-lib/lib/src/wallet.rs` (https://github.com/heliaxdev/namada-apps/blob/main/packages/namada-lib/lib/src/wallet.rs). Creating a new `Wallet` struct with a provided mnemonic generates a seed byte vector and establishes a root extended key. Calling the `derive` method on that `Wallet` providing a derivation path will give us the following struct:

```rust
pub struct DerivedAccount {
    address: String,          // p2pkh address
    wif: String,              // Address in Wallet Import Format (WIF)
    private_key: Vec<u8>,     // Extended Private key
    public_key: Vec<u8>,      // Extended Public key
    secret: Vec<u8>,          // ed25519 secret key
    public: Vec<u8>,          // ed25519 public key
}
```

The ed25519 keys can then be used to initialize an account on the ledger to receive an Established Address.

## Deriving Shielded Addresses

_TBD_

## Resources

- [BIP32 spec for hierarchical deterministric wallets](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki)
- [BIP39 spec for mnemonic seeds](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki)
- [BIP44 spec for hierarchical deterministic wallets](https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki)
- [LedgerHQ - BIP44](https://github.com/LedgerHQ/ledger-live-common/blob/master/docs/derivation.md)
- [SLIP-0044 Registered Coin Types](https://github.com/satoshilabs/slips/blob/master/slip-0044.md)
- [Mnemonic Code Converter](https://iancoleman.io/bip39/) - Useful online utilities to verify derived addresses and keys from specified mnemonic
- [Rust bip32](https://docs.rs/bip32/latest/bip32/)
- [Rust bip0039](https://github.com/koushiro/bip0039)
- [Rust bitcoin](https://github.com/rust-bitcoin/rust-bitcoin)
