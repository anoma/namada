use core::fmt;
use std::str::FromStr;

use derivation_path::{ChildIndex, DerivationPath as DerivationPathInner};
use masp_primitives::zip32;
use namada_core::types::key::SchemeType;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
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

#[derive(Clone, Debug)]
pub struct DerivationPath(DerivationPathInner);

impl DerivationPath {
    fn new<P>(path: P) -> Self
    where
        P: Into<Box<[ChildIndex]>>,
    {
        Self(DerivationPathInner::new(path))
    }

    pub fn is_compatible(&self, scheme: SchemeType) -> bool {
        if let Some(coin_type) = self.0.as_ref().get(1) {
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
        const BIP44_PURPOSE: u32 = 44;
        vec![
            ChildIndex::Hardened(BIP44_PURPOSE),
            match scheme {
                SchemeType::Secp256k1 => ChildIndex::Hardened(ETH_COIN_TYPE),
                SchemeType::Ed25519 => ChildIndex::Hardened(NAMADA_COIN_TYPE),
                SchemeType::Common => unimplemented!("not implemented"),
            },
        ]
    }

    fn bip44(
        scheme: SchemeType,
        account: u32,
        change: u32,
        address: u32,
    ) -> Self {
        let mut indexes = Self::bip44_base_indexes_for_scheme(scheme);
        indexes.push(ChildIndex::Hardened(account));
        indexes.push(ChildIndex::Normal(change));
        indexes.push(ChildIndex::Normal(address));
        Self::new(indexes)
    }

    /// Key path according to zip-0032
    /// https://zips.z.cash/zip-0032#sapling-key-path
    fn zip32(account: u32, address: Option<u32>) -> Self {
        const ZIP32_PURPOSE: u32 = 32;
        let mut indexes = vec![
            ChildIndex::Hardened(ZIP32_PURPOSE),
            ChildIndex::Hardened(NAMADA_COIN_TYPE),
            ChildIndex::Hardened(account),
        ];
        if let Some(address) = address {
            indexes.push(ChildIndex::Normal(address));
        }
        Self::new(indexes)
    }

    fn hardened(&self, scheme: SchemeType) -> Self {
        Self::new(
            self.0
                .into_iter()
                .map(|idx| match scheme {
                    SchemeType::Ed25519 => ChildIndex::Hardened(idx.to_u32()),
                    _ => *idx,
                })
                .collect::<Vec<_>>(),
        )
    }

    pub fn default_for_transparent_scheme(scheme: SchemeType) -> Self {
        let path = Self::bip44(scheme, 0, 0, 0);
        path.hardened(scheme)
    }

    pub fn default_for_shielded() -> Self {
        Self::zip32(0, None)
    }

    pub fn from_path_string(path: &str) -> Result<Self, DerivationPathError> {
        let inner = DerivationPathInner::from_str(path).map_err(|err| {
            DerivationPathError::InvalidDerivationPath(err.to_string())
        })?;
        Ok(Self(inner))
    }

    pub fn from_path_string_for_scheme(
        scheme: SchemeType,
        path: &str,
    ) -> Result<Self, DerivationPathError> {
        Self::from_path_string(path).map(|dp| dp.hardened(scheme))
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

impl FromStr for DerivationPath {
    type Err = DerivationPathError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        DerivationPathInner::from_str(s).map(Self).map_err(|err| {
            DerivationPathError::InvalidDerivationPath(err.to_string())
        })
    }
}

impl Serialize for DerivationPath {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for DerivationPath {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let string = String::deserialize(d)?;
        string.parse().map_err(serde::de::Error::custom)
    }
}

impl IntoHDeriveDerivationPath for DerivationPath {
    fn into(self) -> Result<HDeriveDerivationPath, HDeriveError> {
        HDeriveDerivationPath::from_str(&self.0.to_string())
    }
}

impl From<DerivationPath> for Vec<zip32::ChildIndex> {
    fn from(path: DerivationPath) -> Vec<zip32::ChildIndex> {
        path.0
            .into_iter()
            .map(|idx| match idx {
                ChildIndex::Normal(idx) => zip32::ChildIndex::NonHardened(*idx),
                ChildIndex::Hardened(idx) => zip32::ChildIndex::Hardened(*idx),
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use namada_core::types::key::SchemeType;

    use super::DerivationPath;

    #[test]
    fn path_is_compatible() {
        let path_empty = DerivationPath::from_path_string_for_scheme(
            SchemeType::Secp256k1,
            "m",
        )
        .expect("Path construction cannot fail.");
        assert!(path_empty.is_compatible(SchemeType::Ed25519));
        assert!(path_empty.is_compatible(SchemeType::Secp256k1));
        assert!(path_empty.is_compatible(SchemeType::Common));

        let path_one = DerivationPath::from_path_string_for_scheme(
            SchemeType::Secp256k1,
            "m/44'",
        )
        .expect("Path construction cannot fail.");
        assert!(path_one.is_compatible(SchemeType::Ed25519));
        assert!(path_one.is_compatible(SchemeType::Secp256k1));
        assert!(path_one.is_compatible(SchemeType::Common));

        let path_two = DerivationPath::from_path_string_for_scheme(
            SchemeType::Secp256k1,
            "m/44'/99999'",
        )
        .expect("Path construction cannot fail.");
        assert!(!path_two.is_compatible(SchemeType::Ed25519));
        assert!(!path_two.is_compatible(SchemeType::Secp256k1));
        assert!(path_two.is_compatible(SchemeType::Common));

        let path_eth = DerivationPath::from_path_string_for_scheme(
            SchemeType::Secp256k1,
            "m/44'/60'",
        )
        .expect("Path construction cannot fail.");
        assert!(!path_eth.is_compatible(SchemeType::Ed25519));
        assert!(path_eth.is_compatible(SchemeType::Secp256k1));
        assert!(path_eth.is_compatible(SchemeType::Common));

        let path_nam = DerivationPath::from_path_string_for_scheme(
            SchemeType::Ed25519,
            "m/44'/877'",
        )
        .expect("Path construction cannot fail.");
        assert!(path_nam.is_compatible(SchemeType::Ed25519));
        assert!(!path_nam.is_compatible(SchemeType::Secp256k1));
        assert!(path_nam.is_compatible(SchemeType::Common));
    }
}
