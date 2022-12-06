//! The parameters used for a chain's genesis

use std::collections::HashMap;
use std::fmt::Display;
use std::path::Path;
use std::str::FromStr;

use eyre::{self, Context};
use namada::core::types::key::common;
use namada::core::types::token;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const BALANCES_FILE_NAME: &str = "balances.toml";

/// Genesis balances of all tokens
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(transparent)]
pub struct Balances(pub HashMap<Alias, TokenBalances>);

/// An account alias (a token, special accounts such as faucet etc.)
pub type Alias = String;

/// A hash, `common::PublicKey` or `DkgPublicKey` as a hex string.
#[derive(
    Clone, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord, Hash,
)]
#[serde(transparent)]
pub struct StringEncoded<T>
where
    T: FromStr + Display,
{
    #[serde(
        serialize_with = "encode_via_display",
        deserialize_with = "decode_via_from_str"
    )]
    pub raw: T,
}

#[derive(Error, Debug)]
pub enum StringDecodeError {
    #[error("Invalid string encoding")]
    InvalidStringEncoded,
}

/// Genesis balances for a given token
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TokenBalances(
    pub HashMap<StringEncoded<common::PublicKey>, token::Amount>,
);

impl TokenBalances {
    pub fn get(&self, pk: common::PublicKey) -> Option<&token::Amount> {
        let pk = StringEncoded { raw: pk };
        self.0.get(&pk)
    }
}

pub fn read_balances(path: &Path) -> eyre::Result<Balances> {
    read_toml(path, "Balances")
}

pub fn read_toml<T: DeserializeOwned>(
    path: &Path,
    which_file: &str,
) -> eyre::Result<T> {
    let file_contents = std::fs::read_to_string(&path).wrap_err_with(|| {
        format!(
            "couldn't read {which_file} config file from {}",
            path.to_string_lossy()
        )
    })?;
    toml::from_str(&file_contents).wrap_err_with(|| {
        format!(
            "couldn't parse {which_file} TOML from {}",
            path.to_string_lossy()
        )
    })
}

#[cfg(test)]
mod tests {
    use std::fs;

    use namada::core::types::key;
    use namada::types::key::RefTo;
    use tempfile::tempdir;

    use super::*;

    #[test]
    fn test_read_balances() {
        let test_dir = tempdir().unwrap();
        let path = test_dir.path().join(BALANCES_FILE_NAME);
        let sk = key::testing::keypair_1();
        let pk = sk.ref_to();
        let balance = token::Amount::from(101_000_001);
        let token_alias = "some_token";
        let contents = format!(
            r#"
		[{token_alias}]
		{pk} = {balance}
	    "#
        );
        fs::write(&path, contents).unwrap();

        let balances = read_balances(&path).unwrap();
        let example_balance = balances.0.get(token_alias).unwrap();
        assert_eq!(&balance, example_balance.get(pk).unwrap());
    }
}

fn encode_via_display<S, T>(val: &T, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
    T: Display,
{
    let val_str = val.to_string();
    serde::Serialize::serialize(&val_str, serializer)
}

fn decode_via_from_str<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: serde::Deserializer<'de>,
    T: FromStr,
{
    let val_str: String = serde::Deserialize::deserialize(deserializer)?;
    FromStr::from_str(&val_str).map_err(|_| {
        serde::de::Error::custom(StringDecodeError::InvalidStringEncoded)
    })
}
