//! The templates for balances, parameters and VPs used for a chain's genesis.

use std::collections::HashMap;
use std::path::Path;

use borsh::{BorshDeserialize, BorshSerialize};
use namada::core::types::key::common;
use namada::core::types::string_encoding::StringEncoded;
use namada::core::types::token;
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};

use super::toml_utils::{read_toml, write_toml};
use super::transactions::{self, Transactions};
use crate::wallet::Alias;

pub const BALANCES_FILE_NAME: &str = "balances.toml";
pub const PARAMETERS_FILE_NAME: &str = "parameters.toml";
pub const VPS_FILE_NAME: &str = "validity-predicates.toml";
pub const TOKENS_FILE_NAME: &str = "tokens.toml";
pub const TRANSACTIONS_FILE_NAME: &str = "transactions.toml";

const MAX_TOKEN_BALANCE_SUM: u64 = i64::MAX as u64;

pub fn read_balances(path: &Path) -> eyre::Result<Balances> {
    read_toml(path, "Balances")
}

pub fn read_parameters(path: &Path) -> eyre::Result<Parameters> {
    read_toml(path, "Parameters")
}

pub fn read_validity_predicates(
    path: &Path,
) -> eyre::Result<ValidityPredicates> {
    read_toml(path, "Validity predicates")
}

pub fn read_tokens(path: &Path) -> eyre::Result<Tokens> {
    read_toml(path, "Tokens")
}

pub fn read_transactions(path: &Path) -> eyre::Result<Transactions> {
    read_toml(path, "Transactions")
}

/// Genesis balances of all tokens
#[derive(
    Clone, Debug, Deserialize, Serialize, BorshDeserialize, BorshSerialize,
)]
pub struct Balances {
    pub token: HashMap<Alias, TokenBalances>,
}

/// Genesis balances for a given token
#[derive(
    Clone, Debug, Deserialize, Serialize, BorshDeserialize, BorshSerialize,
)]
pub struct TokenBalances(
    pub HashMap<StringEncoded<common::PublicKey>, token::Amount>,
);

/// Genesis validity predicates
#[derive(
    Clone, Debug, Deserialize, Serialize, BorshDeserialize, BorshSerialize,
)]
pub struct ValidityPredicates {
    // Wasm definitions
    pub wasm: HashMap<String, WasmVpConfig>,
}

#[derive(
    Clone, Debug, Deserialize, Serialize, BorshDeserialize, BorshSerialize,
)]
pub struct WasmVpConfig {
    pub filename: String,
}

#[derive(
    Clone, Debug, Deserialize, Serialize, BorshDeserialize, BorshSerialize,
)]
pub struct Tokens {
    pub token: HashMap<Alias, TokenConfig>,
}

#[derive(
    Clone, Debug, Deserialize, Serialize, BorshDeserialize, BorshSerialize,
)]
pub struct TokenConfig {
    pub vp: String,
}

#[derive(
    Clone, Debug, Deserialize, Serialize, BorshDeserialize, BorshSerialize,
)]
pub struct Parameters {
    pub parameters: ChainParams,
    pub pos_params: PosParams,
    pub gov_params: GovernanceParams,
}

#[derive(
    Clone, Debug, Deserialize, Serialize, BorshDeserialize, BorshSerialize,
)]
pub struct ChainParams {
    /// Name of the native token - this must one of the tokens from
    /// `tokens.toml` file
    pub native_token: Alias,
    /// Minimum number of blocks per epoch.
    // TODO: u64 only works with values up to i64::MAX with toml-rs!
    pub min_num_of_blocks: u64,
    /// Maximum duration per block (in seconds).
    // TODO: this is i64 because datetime wants it
    pub max_expected_time_per_block: i64,
    /// Hashes of whitelisted vps array. `None` value or an empty array
    /// disables whitelisting.
    pub vp_whitelist: Option<Vec<String>>,
    /// Hashes of whitelisted txs array. `None` value or an empty array
    /// disables whitelisting.
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

#[derive(
    Clone, Debug, Deserialize, Serialize, BorshDeserialize, BorshSerialize,
)]
pub struct PosParams {
    /// Maximum number of active validators.
    pub max_validator_slots: u64,
    /// Pipeline length (in epochs).
    pub pipeline_len: u64,
    /// Unbonding length (in epochs).
    pub unbonding_len: u64,
    /// Votes per token.
    pub tm_votes_per_token: Decimal,
    /// Reward for proposing a block.
    pub block_proposer_reward: Decimal,
    /// Reward for voting on a block.
    pub block_vote_reward: Decimal,
    /// Maximum staking APY
    pub max_inflation_rate: Decimal,
    /// Target ratio of staked NAM tokens to total NAM tokens
    pub target_staked_ratio: Decimal,
    /// Portion of a validator's stake that should be slashed on a
    /// duplicate vote.
    pub duplicate_vote_min_slash_rate: Decimal,
    /// Portion of a validator's stake that should be slashed on a
    /// light client attack.
    pub light_client_attack_min_slash_rate: Decimal,
}

#[derive(
    Clone, Debug, Deserialize, Serialize, BorshDeserialize, BorshSerialize,
)]
pub struct GovernanceParams {
    /// Min funds to stake to submit a proposal
    pub min_proposal_fund: u64,
    /// Maximum size of proposal in kibibytes (KiB)
    pub max_proposal_code_size: u64,
    /// Minimum proposal period length in epochs
    pub min_proposal_period: u64,
    /// Maximum proposal period length in epochs
    pub max_proposal_period: u64,
    /// Maximum number of characters in the proposal content
    pub max_proposal_content_size: u64,
    /// Minimum number of epoch between end and grace epoch
    pub min_proposal_grace_epochs: u64,
}

impl TokenBalances {
    pub fn get(&self, pk: common::PublicKey) -> Option<&token::Amount> {
        let pk = StringEncoded { raw: pk };
        self.0.get(&pk)
    }
}

#[derive(
    Clone, Debug, Deserialize, Serialize, BorshDeserialize, BorshSerialize,
)]
pub struct All {
    pub vps: ValidityPredicates,
    pub tokens: Tokens,
    pub balances: Balances,
    pub parameters: Parameters,
    pub transactions: Transactions,
}

impl All {
    pub fn write_toml_files(&self, output_dir: &Path) -> eyre::Result<()> {
        let All {
            vps,
            tokens,
            balances,
            parameters,
            transactions,
        } = self;

        let vps_file = output_dir.join(VPS_FILE_NAME);
        let tokens_file = output_dir.join(TOKENS_FILE_NAME);
        let balances_file = output_dir.join(BALANCES_FILE_NAME);
        let parameters_file = output_dir.join(PARAMETERS_FILE_NAME);
        let transactions_file = output_dir.join(TRANSACTIONS_FILE_NAME);

        write_toml(vps, &vps_file, "Validity predicates")?;
        write_toml(tokens, &tokens_file, "Tokens")?;
        write_toml(balances, &balances_file, "Balances")?;
        write_toml(parameters, &parameters_file, "Parameters")?;
        write_toml(transactions, &transactions_file, "Transactions")?;
        Ok(())
    }

    pub fn read_toml_files(input_dir: &Path) -> eyre::Result<Self> {
        let vps_file = input_dir.join(VPS_FILE_NAME);
        let tokens_file = input_dir.join(TOKENS_FILE_NAME);
        let balances_file = input_dir.join(BALANCES_FILE_NAME);
        let parameters_file = input_dir.join(PARAMETERS_FILE_NAME);
        let transactions_file = input_dir.join(TRANSACTIONS_FILE_NAME);

        let vps = read_toml(&vps_file, "Validity predicates")?;
        let tokens = read_toml(&tokens_file, "Tokens")?;
        let balances = read_toml(&balances_file, "Balances")?;
        let parameters = read_toml(&parameters_file, "Parameters")?;
        let transactions = read_toml(&transactions_file, "Transactions")?;
        Ok(Self {
            vps,
            tokens,
            balances,
            parameters,
            transactions,
        })
    }
}

/// Load genesis templates from the given directory and validate them. Returns
/// `None` when there are some validation issues.
///
/// Note that the validation rules for these templates won't enforce that there
/// is at least one validator with positive voting power. This must be checked
/// when the templates are being used to `init-network`.
pub fn load_and_validate(templates_dir: &Path) -> Option<All> {
    let mut is_valid = true;
    // We don't reuse `All::read_toml_files` here to allow to validate config
    // without all files present.
    let vps_file = templates_dir.join(VPS_FILE_NAME);
    let tokens_file = templates_dir.join(TOKENS_FILE_NAME);
    let balances_file = templates_dir.join(BALANCES_FILE_NAME);
    let parameters_file = templates_dir.join(PARAMETERS_FILE_NAME);
    let transactions_file = templates_dir.join(TRANSACTIONS_FILE_NAME);

    // Check that all required files are present
    let mut check_file_exists = |file: &Path, name: &str| {
        if !file.exists() {
            is_valid = false;
            eprintln!("{name} file is missing at {}", file.to_string_lossy());
        }
    };
    check_file_exists(&vps_file, "Validity predicates");
    check_file_exists(&tokens_file, "Tokens");
    check_file_exists(&balances_file, "Balances");
    check_file_exists(&parameters_file, "Parameters");
    check_file_exists(&transactions_file, "Transactions");

    // Load and parse the files
    let vps = read_validity_predicates(&vps_file);
    let tokens = read_tokens(&tokens_file);
    let balances = read_balances(&balances_file);
    let parameters = read_parameters(&parameters_file);
    let transactions = read_transactions(&transactions_file);

    let eprintln_invalid_file = |err: &eyre::Report, name: &str| {
        eprintln!("{name} file is NOT valid. Failed to read with: {err}");
    };

    // Check the parsing results
    let vps = vps.map_or_else(
        |err| {
            eprintln_invalid_file(&err, "Validity predicates");
            None
        },
        Some,
    );
    let tokens = tokens.map_or_else(
        |err| {
            eprintln_invalid_file(&err, "Tokens");
            None
        },
        Some,
    );
    let balances = balances.map_or_else(
        |err| {
            eprintln_invalid_file(&err, "Balances");
            None
        },
        Some,
    );
    let parameters = parameters.map_or_else(
        |err| {
            eprintln_invalid_file(&err, "Parameters");
            None
        },
        Some,
    );
    let transactions = transactions.map_or_else(
        |err| {
            eprintln_invalid_file(&err, "Transactions");
            None
        },
        Some,
    );

    // Validate each file that could be loaded
    if let Some(vps) = vps.as_ref() {
        if validate_vps(vps) {
            println!("Validity predicates file is valid.");
        } else {
            is_valid = false;
        }
    }

    if let Some(tokens) = tokens.as_ref() {
        if tokens.token.is_empty() {
            is_valid = false;
            eprintln!(
                "Tokens file is invalid. There has to be at least one token."
            );
        }
        println!("Tokens file is valid.");
    }

    if let Some(balances) = balances.as_ref() {
        if validate_balances(balances, tokens.as_ref()) {
            println!("Balances file is valid.");
        } else {
            is_valid = false;
        }
    }

    if let Some(parameters) = parameters.as_ref() {
        if validate_parameters(parameters, vps.as_ref()) {
            println!("Parameters file is valid.");
        } else {
            is_valid = false;
        }
    }

    if let Some(transactions) = transactions.as_ref() {
        if transactions::validate(
            transactions,
            vps.as_ref(),
            balances.as_ref(),
            parameters.as_ref(),
        ) {
            println!("Transactions file is valid.");
        } else {
            is_valid = false;
        }
    }

    match vps {
        Some(vps) if is_valid => Some(All {
            vps: vps,
            tokens: tokens.unwrap(),
            balances: balances.unwrap(),
            parameters: parameters.unwrap(),
            transactions: transactions.unwrap(),
        }),
        _ => None,
    }
}

pub fn validate_vps(vps: &ValidityPredicates) -> bool {
    let mut is_valid = true;
    vps.wasm.iter().for_each(|(name, config)| {
        if !config.filename.ends_with(".wasm") {
            eprintln!(
                "Invalid validity predicate \"{name}\" configuration. Only \
                 \".wasm\" filenames are currently supported."
            );
            is_valid = false;
        }
    });
    is_valid
}

pub fn validate_parameters(
    parameters: &Parameters,
    vps: Option<&ValidityPredicates>,
) -> bool {
    let mut is_valid = true;
    let implicit_vp = &parameters.parameters.implicit_vp;
    if !vps
        .map(|vps| vps.wasm.contains_key(implicit_vp))
        .unwrap_or_default()
    {
        eprintln!(
            "Implicit VP \"{implicit_vp}\" not found in the Validity \
             predicates files."
        );
        is_valid = false;
    }
    is_valid
}

pub fn validate_balances(balances: &Balances, tokens: Option<&Tokens>) -> bool {
    let mut is_valid = true;
    balances.token.iter().for_each(|(token, next)| {
        // Every token alias used in Balances file must be present in
        // the Tokens file
        if !tokens
            .as_ref()
            .map(|tokens| tokens.token.contains_key(token))
            .unwrap_or_default()
        {
            is_valid = false;
            eprintln!(
                "Token \"{token}\" from the Balances file is not present in \
                 the Tokens file."
            )
        }

        // Check the sum of balances
        let sum = next.0.values().try_fold(
            token::Amount::default(),
            |acc, amount| {
                let res = acc.checked_add(*amount);
                if res.as_ref().is_none() {
                    is_valid = false;
                    eprintln!(
                        "Balances for token {token} overflow `token::Amount`"
                    );
                }
                res
            },
        );
        if sum.is_none() || u64::from(sum.unwrap()) > MAX_TOKEN_BALANCE_SUM {
            eprintln!(
                "The sum of balances for token {token} is greater than \
                 {MAX_TOKEN_BALANCE_SUM}"
            );
            is_valid = false;
        }
    });
    is_valid
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;

    use namada::core::types::key;
    use namada::types::key::RefTo;
    use tempfile::tempdir;

    use super::*;

    /// Validate the `genesis/localnet` genesis templates.
    #[test]
    fn test_validate_localnet_genesis_templates() {
        let templates_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .join("genesis/localnet");
        assert!(
            load_and_validate(&templates_dir).is_some(),
            "Localnet genesis templates must be valid"
        );
    }

    /// Validate the `genesis/starter` genesis templates.
    #[test]
    fn test_validate_starter_genesis_templates() {
        let templates_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .join("genesis/starter");
        assert!(
            load_and_validate(&templates_dir).is_some(),
            "Starter genesis templates must be valid"
        );
    }

    #[test]
    fn test_read_balances() {
        let test_dir = tempdir().unwrap();
        let path = test_dir.path().join(BALANCES_FILE_NAME);
        let sk = key::testing::keypair_1();
        let pk = sk.ref_to();
        let balance = token::Amount::from(101_000_001);
        let token_alias = Alias::from("Some_token".to_string());
        let contents = format!(
            r#"
		[token.{token_alias}]
		{pk} = {balance}
	    "#
        );
        fs::write(&path, contents).unwrap();

        let balances = read_balances(&path).unwrap();
        let example_balance = balances.token.get(&token_alias).unwrap();
        assert_eq!(&balance, example_balance.get(pk).unwrap());
    }
}
