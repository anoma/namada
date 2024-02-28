//! Wallet address and key aliases.

use std::convert::Infallible;
use std::fmt::Display;
use std::hash::Hash;
use std::io::Read;
use std::str::FromStr;

use borsh::{BorshDeserialize, BorshSerialize};
use namada_core::address::{Address, InternalAddress};
use serde::{Deserialize, Serialize};

/// Aliases created from raw strings are kept in-memory as given, but their
/// `Serialize` and `Display` instance converts them to lowercase. Their
/// `PartialEq` instance is case-insensitive.
#[derive(Clone, Debug, Default, Eq)]
pub struct Alias(String);

impl Alias {
    /// Normalize an alias to lower-case
    pub fn normalize(&self) -> String {
        self.0.to_lowercase()
    }

    /// Returns the length of the underlying `String`.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Is the underlying `String` empty?
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// If the alias is reserved for an internal address,
    /// return that address
    pub fn is_reserved(alias: impl AsRef<str>) -> Option<Address> {
        InternalAddress::try_from_alias(alias.as_ref()).map(Address::Internal)
    }
}

impl BorshSerialize for Alias {
    fn serialize<W: std::io::Write>(
        &self,
        writer: &mut W,
    ) -> std::io::Result<()> {
        BorshSerialize::serialize(&self.normalize(), writer)
    }
}

impl BorshDeserialize for Alias {
    fn deserialize(buf: &mut &[u8]) -> std::io::Result<Self> {
        let raw: String = BorshDeserialize::deserialize(buf)?;
        Ok(Self::from(raw))
    }

    fn deserialize_reader<R: Read>(reader: &mut R) -> std::io::Result<Self> {
        let raw: String = BorshDeserialize::deserialize_reader(reader)?;
        Ok(Self::from(raw))
    }
}

impl Serialize for Alias {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        Serialize::serialize(&self.normalize(), serializer)
    }
}

impl<'de> Deserialize<'de> for Alias {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw: String = Deserialize::deserialize(deserializer)?;
        Ok(Self::from(raw))
    }
}

impl PartialEq for Alias {
    fn eq(&self, other: &Self) -> bool {
        self.normalize() == other.normalize()
    }
}

impl PartialOrd for Alias {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Alias {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.normalize().cmp(&other.normalize())
    }
}

impl Hash for Alias {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.normalize().hash(state);
    }
}

impl<T> From<T> for Alias
where
    T: AsRef<str>,
{
    fn from(raw: T) -> Self {
        Self(raw.as_ref().to_lowercase())
    }
}

impl From<Alias> for String {
    fn from(alias: Alias) -> Self {
        alias.normalize()
    }
}

impl<'a> From<&'a Alias> for String {
    fn from(alias: &'a Alias) -> Self {
        alias.normalize()
    }
}

impl Display for Alias {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.normalize().fmt(f)
    }
}

impl FromStr for Alias {
    type Err = Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self::from(s))
    }
}

impl AsRef<str> for &Alias {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

/// Default alias of a validator's account key
pub fn validator_key(validator_alias: &Alias) -> Alias {
    format!("{validator_alias}-validator-key").into()
}

/// Default alias of a validator's consensus key
pub fn validator_consensus_key(validator_alias: &Alias) -> Alias {
    format!("{validator_alias}-consensus-key").into()
}

/// Default alias of a validator's Tendermint node key
pub fn validator_tendermint_node_key(validator_alias: &Alias) -> Alias {
    format!("{validator_alias}-tendermint-node-key").into()
}
