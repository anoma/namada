use core::fmt;
use std::str::FromStr;

use derivation_path::{ChildIndex, DerivationPath as DerivationPathInner};
use namada::types::key::SchemeType;
use thiserror::Error;
use tiny_hderive::bip44::{
    DerivationPath as HDeriveDerivationPath,
    IntoDerivationPath as IntoHDeriveDerivationPath,
};
use tiny_hderive::Error as HDeriveError;

const ETH_COIN_TYPE: u32 = 60;
const NAMADA_COIN_TYPE: u32 = 877;

#[derive(Error, Debug)]
pub enum DerivationPathError {
    #[error("invalid derivation path: {0}")]
    InvalidDerivationPath(String),
}

#[derive(Clone)]
pub struct DerivationPath(DerivationPathInner);

impl DerivationPath {
    fn new<P>(path: P) -> Self
    where
        P: Into<Box<[ChildIndex]>>,
    {
        Self(DerivationPathInner::new(path))
    }

    pub fn empty() -> Self {
        Self::new(vec![])
    }

    fn base_indexes_for_scheme(scheme: SchemeType) -> Vec<ChildIndex> {
        vec![
            ChildIndex::Hardened(44),
            match scheme {
                SchemeType::Secp256k1 => ChildIndex::Hardened(ETH_COIN_TYPE),
                SchemeType::Ed25519 => ChildIndex::Hardened(NAMADA_COIN_TYPE),
                SchemeType::Common => unimplemented!("not implemented"),
            },
        ]
    }

    fn index_for_scheme(scheme: SchemeType, idx: u32) -> ChildIndex {
        match scheme {
            SchemeType::Secp256k1 => ChildIndex::Normal(idx),
            SchemeType::Ed25519 => ChildIndex::Hardened(idx),
            SchemeType::Common => unimplemented!("not implemented"),
        }
    }

    fn bip44(
        scheme: SchemeType,
        account: Option<u32>,
        change: Option<u32>,
        address: Option<u32>,
    ) -> Self {
        let mut indexes = Self::base_indexes_for_scheme(scheme);
        if let Some(account) = account {
            indexes.push(Self::index_for_scheme(scheme, account));
            if let Some(change) = change {
                indexes.push(Self::index_for_scheme(scheme, change));
                if let Some(address) = address {
                    indexes.push(Self::index_for_scheme(scheme, address));
                }
            }
        }
        Self::new(indexes)
    }

    pub fn default_for_scheme(scheme: SchemeType) -> Self {
        Self::bip44(scheme, Some(0), Some(0), Some(0))
    }

    pub fn from_path_str(path: &str) -> Result<Self, DerivationPathError> {
        let inner = DerivationPathInner::from_str(path).map_err(|err| {
            DerivationPathError::InvalidDerivationPath(err.to_string())
        })?;
        Ok(Self::new(
            inner
                .into_iter()
                .map(|c| ChildIndex::Hardened(c.to_u32()))
                .collect::<Vec<_>>(),
        ))
    }

    pub fn path(&self) -> &[ChildIndex] {
        self.0.path()
    }
}

impl fmt::Display for DerivationPath {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

impl IntoHDeriveDerivationPath for DerivationPath {
    fn into(self) -> Result<HDeriveDerivationPath, HDeriveError> {
        HDeriveDerivationPath::from_str(&self.0.to_string())
    }
}
