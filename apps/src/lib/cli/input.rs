//! CLI input types can be used for command arguments

use std::convert::Infallible;
use std::fmt::Display;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr;

use anoma::types::key::ed25519::PublicKey;
use anoma::types::{address, token};
use libp2p::Multiaddr;
use thiserror::Error;

use super::Context;

/// CLI argument that can be parsed from a string and/or found via the
/// [`Context`].
pub trait ArgInput: Sized {
    type Err: Display;
    fn try_from_raw(ctx: &Context, s: &str) -> Result<Self, Self::Err>;
}

#[derive(Debug, Error)]
pub enum ArgError {
    #[error("Unknown {0}")]
    Unknown(&'static str),
}

impl ArgInput for address::Address {
    type Err = ArgError;

    fn try_from_raw(ctx: &Context, s: &str) -> Result<Self, Self::Err> {
        // An address can be either raw (bech32m encoding)
        FromStr::from_str(s)
            // Or it can be an alias that may be found in the wallet
            .or_else(|_| {
                ctx.wallet
                    .find_address(s)
                    .ok_or(ArgError::Unknown("address"))
                    .map(|address| address.clone())
            })
    }
}

impl ArgInput for PublicKey {
    type Err = ArgError;

    fn try_from_raw(ctx: &Context, s: &str) -> Result<Self, Self::Err> {
        // A public key can be either raw (hex string)
        FromStr::from_str(s)
            // Or it can be an alias that may be found in the wallet
            .or_else(|_| {
                ctx.wallet
                    .find_key(s)
                    .map_err(|_err| ArgError::Unknown("public key"))
                    .map(|keypair| keypair.get().public.clone())
            })
    }
}

impl ArgInput for String {
    type Err = Infallible;

    fn try_from_raw(_ctx: &Context, s: &str) -> Result<Self, Self::Err> {
        Ok(s.to_owned())
    }
}

impl ArgInput for PathBuf {
    type Err = Infallible;

    fn try_from_raw(_ctx: &Context, s: &str) -> Result<Self, Self::Err> {
        Ok(s.into())
    }
}

impl ArgInput for token::Amount {
    type Err = <Self as FromStr>::Err;

    fn try_from_raw(_ctx: &Context, s: &str) -> Result<Self, Self::Err> {
        FromStr::from_str(s)
    }
}

impl ArgInput for Multiaddr {
    // The multiaddr parse error type is private
    type Err = <Self as FromStr>::Err;

    fn try_from_raw(_ctx: &Context, s: &str) -> Result<Self, Self::Err> {
        FromStr::from_str(s)
    }
}

impl ArgInput for SocketAddr {
    type Err = <Self as FromStr>::Err;

    fn try_from_raw(_ctx: &Context, s: &str) -> Result<Self, Self::Err> {
        FromStr::from_str(s)
    }
}

impl ArgInput for tendermint::net::Address {
    type Err = <Self as FromStr>::Err;

    fn try_from_raw(_ctx: &Context, s: &str) -> Result<Self, Self::Err> {
        FromStr::from_str(s)
    }
}
