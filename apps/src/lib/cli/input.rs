//! CLI input types can be used for command arguments

use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr;

use anoma::types::key::ed25519::{PublicKey, PublicKeyHash};
use anoma::types::storage::Epoch;
use anoma::types::{address, token};
use libp2p::Multiaddr;

use super::Context;
use crate::cli::safe_exit;
use crate::wallet::DecryptedKeypair;

/// CLI argument that can be parsed from a string and/or found via the
/// [`Context`].
pub trait ArgInput: Sized {
    fn from_raw(ctx: &Context, s: &str) -> Self;
}

impl ArgInput for address::Address {
    fn from_raw(ctx: &Context, s: &str) -> Self {
        // An address can be either raw (bech32m encoding)
        FromStr::from_str(s)
            // Or it can be an alias that may be found in the wallet
            .unwrap_or_else(|_| {
                ctx.wallet
                    .find_address(s)
                    .unwrap_or_else(|| {
                        eprintln!("Unknown address {}", s);
                        safe_exit(1)
                    })
                    .clone()
            })
    }
}

/// A raw address value that is not being looked-up from the wallet. This
/// should only be used for wallet commands that expect a address value.
#[derive(Clone, Debug)]
pub struct RawAddress(pub address::Address);

impl ArgInput for RawAddress {
    fn from_raw(_ctx: &Context, s: &str) -> Self {
        let address: address::Address =
            FromStr::from_str(s).unwrap_or_else(|err| {
                eprintln!(
                    "Invalid address: {}. Expected bech32m encoded string",
                    err
                );
                safe_exit(1)
            });
        Self(address)
    }
}

/// Lazily evaluated public key, either a raw value (hexadecimal encoding), or
/// looked-up from a wallet by a public key hash or an alias.
/// We evaluate the public key lazily, because it might need to be decrypted.
#[derive(Clone, Debug)]
pub struct LazyWalletPublicKey {
    raw_arg: String,
}

impl LazyWalletPublicKey {
    pub fn get(&self, ctx: &Context) -> PublicKey {
        // A public key can be either a raw public key in hex string
        FromStr::from_str(&self.raw_arg).unwrap_or_else(|_parse_err| {
            // Or it can be a public key hash in hex string
            FromStr::from_str(&self.raw_arg)
                .map(|pkh: PublicKeyHash| {
                    let key = ctx.wallet.find_key_by_pkh(&pkh).unwrap();
                    key.get().public.clone()
                })
                // Or it can be an alias that may be found in the wallet
                .unwrap_or_else(|_parse_err| {
                    let key = ctx.wallet.find_key(&self.raw_arg).unwrap();
                    key.get().public.clone()
                })
        })
    }
}

impl ArgInput for LazyWalletPublicKey {
    fn from_raw(_ctx: &Context, s: &str) -> Self {
        Self { raw_arg: s.into() }
    }
}

/// A raw public key value that is not being looked-up from the wallet. This
/// should only be used for wallet commands that expect a raw public key value.
#[derive(Clone, Debug)]
pub struct RawPublicKey(pub PublicKey);

impl ArgInput for RawPublicKey {
    fn from_raw(_ctx: &Context, s: &str) -> Self {
        let pk: PublicKey = FromStr::from_str(s).unwrap_or_else(|err| {
            eprintln!(
                "Invalid public key: {}. Expected hexadecimal string",
                err
            );
            safe_exit(1)
        });
        Self(pk)
    }
}

/// Lazily evaluated keypair, looked-up from a wallet by a public key, public
/// key hash or an alias.
#[derive(Clone, Debug)]
pub struct LazyWalletKeypair {
    raw_arg: String,
}

impl LazyWalletKeypair {
    pub fn get<'a>(&'a self, ctx: &'a Context) -> DecryptedKeypair<'a> {
        ctx.wallet
            .find_key(&self.raw_arg)
            .unwrap_or_else(|_find_err| {
                eprintln!("Unknown key {}", self.raw_arg);
                safe_exit(1)
            })
    }
}

impl ArgInput for LazyWalletKeypair {
    fn from_raw(_ctx: &Context, s: &str) -> Self {
        Self { raw_arg: s.into() }
    }
}

impl ArgInput for String {
    fn from_raw(_ctx: &Context, s: &str) -> Self {
        s.to_owned()
    }
}

impl ArgInput for PathBuf {
    fn from_raw(_ctx: &Context, s: &str) -> Self {
        s.into()
    }
}

impl ArgInput for token::Amount {
    fn from_raw(_ctx: &Context, s: &str) -> Self {
        FromStr::from_str(s).unwrap_or_else(|err| {
            eprintln!("Invalid token amount: {}", err);
            safe_exit(1)
        })
    }
}

impl ArgInput for Multiaddr {
    fn from_raw(_ctx: &Context, s: &str) -> Self {
        FromStr::from_str(s).unwrap_or_else(|err| {
            eprintln!("Invalid multi-address: {}", err);
            safe_exit(1)
        })
    }
}

impl ArgInput for SocketAddr {
    fn from_raw(_ctx: &Context, s: &str) -> Self {
        FromStr::from_str(s).unwrap_or_else(|err| {
            eprintln!("Invalid socket address: {}", err);
            safe_exit(1)
        })
    }
}

impl ArgInput for tendermint::net::Address {
    fn from_raw(_ctx: &Context, s: &str) -> Self {
        FromStr::from_str(s).unwrap_or_else(|err| {
            eprintln!("Invalid remote address (TCP or UNIX socket): {}", err);
            safe_exit(1)
        })
    }
}

impl ArgInput for Epoch {
    fn from_raw(_ctx: &Context, s: &str) -> Self {
        FromStr::from_str(s).unwrap_or_else(|err| {
            eprintln!("Invalid epoch: {}", err);
            safe_exit(1)
        })
    }
}
