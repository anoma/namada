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

    pub fn is_compatible(&self, scheme: SchemeType) -> bool {
        let mut it = self.0.into_iter();
        let _ = it.next();
        if let Some(coin_type) = it.next() {
            let coin_type = coin_type.to_u32();
            match scheme {
                SchemeType::Ed25519 => coin_type == NAMADA_COIN_TYPE,
                SchemeType::Secp256k1 => coin_type == ETH_COIN_TYPE,
                _ => true,
            }
        } else {
            true
        }
    }

    fn bip44_base_indexes_for_scheme(scheme: SchemeType) -> Vec<ChildIndex> {
        vec![
            ChildIndex::Hardened(44),
            match scheme {
                SchemeType::Secp256k1 => ChildIndex::Hardened(ETH_COIN_TYPE),
                SchemeType::Ed25519 => ChildIndex::Hardened(NAMADA_COIN_TYPE),
                SchemeType::Common => unimplemented!("not implemented"),
            },
        ]
    }

    fn bip44(
        scheme: SchemeType,
        account: Option<u32>,
        change: Option<u32>,
        address: Option<u32>,
    ) -> Self {
        let mut indexes = Self::bip44_base_indexes_for_scheme(scheme);
        if let Some(account) = account {
            indexes.push(ChildIndex::Hardened(account));
            if let Some(change) = change {
                indexes.push(ChildIndex::Normal(change));
                if let Some(address) = address {
                    indexes.push(ChildIndex::Normal(address));
                }
            }
        }
        Self::new(indexes)
    }

    pub fn default_for_scheme(scheme: SchemeType) -> Self {
        Self::bip44(scheme, Some(0), Some(0), Some(0))
    }

    pub fn from_path_str(
        scheme: SchemeType,
        path: &str,
    ) -> Result<Self, DerivationPathError> {
        let inner = DerivationPathInner::from_str(path).map_err(|err| {
            DerivationPathError::InvalidDerivationPath(err.to_string())
        })?;
        Ok(Self::new(
            inner
                .into_iter()
                .map(|idx| match scheme {
                    SchemeType::Ed25519 => ChildIndex::Hardened(idx.to_u32()),
                    _ => *idx,
                })
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

#[cfg(test)]
mod tests {
    use namada::types::key::SchemeType;

    use super::DerivationPath;

    #[test]
    fn path_is_compatible() {
        let path_empty =
            DerivationPath::from_path_str(SchemeType::Secp256k1, "m")
                .expect("Path construction cannot fail.");
        assert!(path_empty.is_compatible(SchemeType::Ed25519));
        assert!(path_empty.is_compatible(SchemeType::Secp256k1));
        assert!(path_empty.is_compatible(SchemeType::Common));

        let path_one =
            DerivationPath::from_path_str(SchemeType::Secp256k1, "m/44'")
                .expect("Path construction cannot fail.");
        assert!(path_one.is_compatible(SchemeType::Ed25519));
        assert!(path_one.is_compatible(SchemeType::Secp256k1));
        assert!(path_one.is_compatible(SchemeType::Common));

        let path_two = DerivationPath::from_path_str(
            SchemeType::Secp256k1,
            "m/44'/99999'",
        )
        .expect("Path construction cannot fail.");
        assert!(!path_two.is_compatible(SchemeType::Ed25519));
        assert!(!path_two.is_compatible(SchemeType::Secp256k1));
        assert!(path_two.is_compatible(SchemeType::Common));

        let path_eth =
            DerivationPath::from_path_str(SchemeType::Secp256k1, "m/44'/60'")
                .expect("Path construction cannot fail.");
        assert!(!path_eth.is_compatible(SchemeType::Ed25519));
        assert!(path_eth.is_compatible(SchemeType::Secp256k1));
        assert!(path_eth.is_compatible(SchemeType::Common));

        let path_nam =
            DerivationPath::from_path_str(SchemeType::Ed25519, "m/44'/877'")
                .expect("Path construction cannot fail.");
        assert!(path_nam.is_compatible(SchemeType::Ed25519));
        assert!(!path_nam.is_compatible(SchemeType::Secp256k1));
        assert!(path_nam.is_compatible(SchemeType::Common));
    }
}
