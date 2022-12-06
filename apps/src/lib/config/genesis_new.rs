//! The parameters used for a chain's genesis

use std::collections::HashMap;
use std::fmt::Display;
use std::path::Path;
use std::str::FromStr;

use eyre::{self, Context};
use namada::core::types::key::common;
use namada::core::types::token;
use rust_decimal::Decimal;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const BALANCES_FILE_NAME: &str = "balances.toml";
pub const PARAMETERS_FILE_NAME: &str = "parameters.toml";

pub fn read_balances(path: &Path) -> eyre::Result<Balances> {
    read_toml(path, "Balances")
}

pub fn read_parameters(path: &Path) -> eyre::Result<Parameters> {
    read_toml(path, "Parameters")
}

/// Genesis balances of all tokens
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(transparent)]
pub struct Balances(pub HashMap<Alias, TokenBalances>);

/// Genesis balances for a given token
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TokenBalances(
    pub HashMap<StringEncoded<common::PublicKey>, token::Amount>,
);

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Parameters {
    pub parameters: ChainParams,
    pub pos_params: PosParams,
    pub gov_params: GovernanceParams,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ChainParams {
    // Minimum number of blocks per epoch.
    // XXX: u64 only works with values up to i64::MAX with toml-rs!
    pub min_num_of_blocks: u64,
    // Maximum duration per block (in seconds).
    // TODO: this is i64 because datetime wants it
    pub max_expected_time_per_block: i64,
    // Hashes of whitelisted vps array. `None` value or an empty array
    // disables whitelisting.
    pub vp_whitelist: Option<Vec<String>>,
    // Hashes of whitelisted txs array. `None` value or an empty array
    // disables whitelisting.
    pub tx_whitelist: Option<Vec<String>>,
    /// Filename of implicit accounts validity predicate WASM code
    pub implicit_vp: String,
    /// Expected number of epochs per year
    pub epochs_per_year: u64,
    /// PoS gain p
    pub pos_gain_p: Decimal,
    /// PoS gain d
    pub pos_gain_d: Decimal,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PosParams {
    // Maximum number of active validators.
    pub max_validator_slots: u64,
    // Pipeline length (in epochs).
    pub pipeline_len: u64,
    // Unbonding length (in epochs).
    pub unbonding_len: u64,
    // Votes per token.
    pub tm_votes_per_token: Decimal,
    // Reward for proposing a block.
    pub block_proposer_reward: Decimal,
    // Reward for voting on a block.
    pub block_vote_reward: Decimal,
    // Maximum staking APY
    pub max_inflation_rate: Decimal,
    // Target ratio of staked NAM tokens to total NAM tokens
    pub target_staked_ratio: Decimal,
    // Portion of a validator's stake that should be slashed on a
    // duplicate vote.
    pub duplicate_vote_min_slash_rate: Decimal,
    // Portion of a validator's stake that should be slashed on a
    // light client attack.
    pub light_client_attack_min_slash_rate: Decimal,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct GovernanceParams {
    // Min funds to stake to submit a proposal
    pub min_proposal_fund: u64,
    // Maximum size of proposal in kibibytes (KiB)
    pub max_proposal_code_size: u64,
    // Minimum proposal period length in epochs
    pub min_proposal_period: u64,
    // Maximum proposal period length in epochs
    pub max_proposal_period: u64,
    // Maximum number of characters in the proposal content
    pub max_proposal_content_size: u64,
    // Minimum number of epoch between end and grace epoch
    pub min_proposal_grace_epochs: u64,
}

/// An account alias (a token, special accounts such as faucet etc.)
pub type Alias = String;

impl TokenBalances {
    pub fn get(&self, pk: common::PublicKey) -> Option<&token::Amount> {
        let pk = StringEncoded { raw: pk };
        self.0.get(&pk)
    }
}

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
