//! The templates for balances, parameters and VPs used for a chain's genesis.

use std::collections::BTreeMap;
use std::path::Path;

use borsh::{BorshDeserialize, BorshSerialize};
use namada::core::ledger::testnet_pow;
use namada::core::types::key::common;
use namada::core::types::string_encoding::StringEncoded;
use namada::core::types::{ethereum_structs, token};
use namada::eth_bridge::parameters::{Contracts, MinimumConfirmations};
use namada::types::chain::ProposalBytes;
use namada::types::dec::Dec;
use namada::types::token::{Amount, Denomination, NATIVE_MAX_DECIMAL_PLACES};
use serde::{Deserialize, Serialize};

use super::toml_utils::{read_toml, write_toml};
use super::transactions::{self, Transactions};
use crate::config::genesis::transactions::{
    BondTx, SignedBondTx, SignedTransferTx, TransferTx,
};
use crate::wallet::Alias;

pub const BALANCES_FILE_NAME: &str = "balances.toml";
pub const PARAMETERS_FILE_NAME: &str = "parameters.toml";
pub const VPS_FILE_NAME: &str = "validity-predicates.toml";
pub const TOKENS_FILE_NAME: &str = "tokens.toml";
pub const TRANSACTIONS_FILE_NAME: &str = "transactions.toml";

const MAX_TOKEN_BALANCE_SUM: u64 = i64::MAX as u64;

/// Note that these balances must be crossed-checked with the token configs
/// to correctly represent the underlying amounts.
pub fn read_balances(path: &Path) -> eyre::Result<UndenominatedBalances> {
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

pub fn read_transactions(
    path: &Path,
) -> eyre::Result<Transactions<Unvalidated>> {
    read_toml(path, "Transactions")
}

/// Genesis balances of all tokens
#[derive(
    Clone,
    Debug,
    Deserialize,
    Serialize,
    BorshDeserialize,
    BorshSerialize,
    PartialEq,
    Eq,
)]
pub struct UndenominatedBalances {
    token: BTreeMap<Alias, RawTokenBalances>,
}

impl UndenominatedBalances {
    /// Use the denom in `TokenConfig` to correctly interpret the balances
    /// to the right denomination.
    pub fn denominate(
        self,
        tokens: &Tokens,
    ) -> eyre::Result<DenominatedBalances> {
        let mut balances = DenominatedBalances {
            token: BTreeMap::new(),
        };
        for (alias, bals) in self.token {
            let denom = tokens
                .token
                .get(&alias)
                .ok_or_else(|| {
                    eyre::eyre!(
                        "A balance of token {} was found, but this token was \
                         not found in the `tokens.toml` file",
                        alias
                    )
                })?
                .denom;
            let mut denominated_bals = BTreeMap::new();
            for (pk, bal) in bals.0.into_iter() {
                let denominated = bal.increase_precision(denom)?;
                denominated_bals.insert(pk, denominated);
            }
            balances
                .token
                .insert(alias, TokenBalances(denominated_bals));
        }
        Ok(balances)
    }
}

/// Genesis balances of all tokens
#[derive(
    Clone,
    Debug,
    Deserialize,
    Serialize,
    BorshDeserialize,
    BorshSerialize,
    PartialEq,
    Eq,
)]
pub struct DenominatedBalances {
    pub token: BTreeMap<Alias, TokenBalances>,
}

/// Genesis balances for a given token
#[derive(
    Clone,
    Debug,
    Deserialize,
    Serialize,
    BorshDeserialize,
    BorshSerialize,
    PartialEq,
    Eq,
)]
pub struct RawTokenBalances(
    pub BTreeMap<StringEncoded<common::PublicKey>, token::DenominatedAmount>,
);

/// Genesis balances for a given token
#[derive(
    Clone,
    Debug,
    Deserialize,
    Serialize,
    BorshDeserialize,
    BorshSerialize,
    PartialEq,
    Eq,
)]
pub struct TokenBalances(
    pub BTreeMap<StringEncoded<common::PublicKey>, token::DenominatedAmount>,
);

/// Genesis validity predicates
#[derive(
    Clone,
    Debug,
    Deserialize,
    Serialize,
    BorshDeserialize,
    BorshSerialize,
    PartialEq,
    Eq,
)]
pub struct ValidityPredicates {
    // Wasm definitions
    pub wasm: BTreeMap<String, WasmVpConfig>,
}

#[derive(
    Clone,
    Debug,
    Deserialize,
    Serialize,
    BorshDeserialize,
    BorshSerialize,
    PartialEq,
    Eq,
)]
pub struct WasmVpConfig {
    pub filename: String,
}

#[derive(
    Clone,
    Debug,
    Deserialize,
    Serialize,
    BorshDeserialize,
    BorshSerialize,
    PartialEq,
    Eq,
)]
pub struct Tokens {
    pub token: BTreeMap<Alias, TokenConfig>,
}

#[derive(
    Clone,
    Debug,
    Deserialize,
    Serialize,
    BorshDeserialize,
    BorshSerialize,
    PartialEq,
    Eq,
)]
pub struct TokenConfig {
    pub denom: Denomination,
}

#[derive(
    Clone,
    Debug,
    Deserialize,
    Serialize,
    BorshDeserialize,
    BorshSerialize,
    PartialEq,
    Eq,
)]
pub struct Parameters {
    pub parameters: ChainParams,
    pub pos_params: PosParams,
    pub gov_params: GovernanceParams,
    pub eth_bridge_params: Option<EthBridgeParams>,
}

#[derive(
    Clone,
    Debug,
    Deserialize,
    Serialize,
    BorshDeserialize,
    BorshSerialize,
    PartialEq,
    Eq,
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
    /// Max payload size, in bytes, for a tx batch proposal.
    ///
    /// Block proposers may never return a `PrepareProposal`
    /// response containing `txs` with a byte length greater
    /// than whatever is configured through this parameter.
    ///
    /// Note that this parameter's value will always be strictly
    /// smaller than a Tendermint block's `MaxBytes` consensus
    /// parameter. Currently, we hard cap `max_proposal_bytes`
    /// at 90 MiB in Namada, which leaves at least 10 MiB of
    /// room for header data, evidence and protobuf
    /// serialization overhead in Tendermint blocks.
    pub max_proposal_bytes: ProposalBytes,
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
    pub pos_gain_p: Dec,
    /// PoS gain d
    pub pos_gain_d: Dec,
    #[cfg(not(feature = "mainnet"))]
    /// Fix wrapper tx fees
    pub wrapper_tx_fees: Option<token::Amount>,
    #[cfg(not(feature = "mainnet"))]
    /// Testnet faucet PoW difficulty - defaults to `0` when not set
    pub faucet_pow_difficulty: Option<testnet_pow::Difficulty>,
    #[cfg(not(feature = "mainnet"))]
    /// Testnet faucet withdrawal limit - defaults to 1000 NAM when not set
    pub faucet_withdrawal_limit: Option<token::Amount>,
}

#[derive(
    Clone,
    Debug,
    Deserialize,
    Serialize,
    BorshDeserialize,
    BorshSerialize,
    PartialEq,
    Eq,
)]
pub struct PosParams {
    /// Maximum number of active validators.
    pub max_validator_slots: u64,
    /// Pipeline length (in epochs).
    pub pipeline_len: u64,
    /// Unbonding length (in epochs).
    pub unbonding_len: u64,
    /// Votes per token.
    pub tm_votes_per_token: Dec,
    /// Reward for proposing a block.
    pub block_proposer_reward: Dec,
    /// Reward for voting on a block.
    pub block_vote_reward: Dec,
    /// Maximum staking APY
    pub max_inflation_rate: Dec,
    /// Target ratio of staked NAM tokens to total NAM tokens
    pub target_staked_ratio: Dec,
    /// Portion of a validator's stake that should be slashed on a
    /// duplicate vote.
    pub duplicate_vote_min_slash_rate: Dec,
    /// Portion of a validator's stake that should be slashed on a
    /// light client attack.
    pub light_client_attack_min_slash_rate: Dec,
    /// Number of epochs above and below (separately) the current epoch to
    /// consider when doing cubic slashing
    pub cubic_slashing_window_length: u64,
    /// The minimum amount of bonded tokens that a validator needs to be in
    /// either the `consensus` or `below_capacity` validator sets
    pub validator_stake_threshold: token::Amount,
}

#[derive(
    Clone,
    Debug,
    Deserialize,
    Serialize,
    BorshDeserialize,
    BorshSerialize,
    PartialEq,
    Eq,
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

#[derive(
    Clone,
    Debug,
    Deserialize,
    Serialize,
    BorshDeserialize,
    BorshSerialize,
    PartialEq,
    Eq,
)]
pub struct EthBridgeParams {
    /// Initial Ethereum block height when events will first be extracted from.
    pub eth_start_height: ethereum_structs::BlockHeight,
    /// Minimum number of confirmations needed to trust an Ethereum branch.
    /// This must be at least one.
    pub min_confirmations: MinimumConfirmations,
    /// The addresses of the Ethereum contracts that need to be directly known
    /// by validators.
    pub contracts: Contracts,
}

impl TokenBalances {
    pub fn get(&self, pk: common::PublicKey) -> Option<token::Amount> {
        let pk = StringEncoded { raw: pk };
        self.0.get(&pk).map(|amt| amt.amount)
    }
}
#[derive(
    Clone,
    Debug,
    Deserialize,
    Serialize,
    BorshDeserialize,
    BorshSerialize,
    PartialEq,
    Eq,
)]
pub struct Unvalidated {}

#[derive(
    Clone,
    Debug,
    Deserialize,
    Serialize,
    BorshDeserialize,
    BorshSerialize,
    PartialEq,
    Eq,
)]
pub struct Validated {}

pub trait TemplateValidation {
    type Balances: for<'a> Deserialize<'a>
        + Serialize
        + Clone
        + std::fmt::Debug
        + BorshSerialize
        + BorshDeserialize
        + PartialEq
        + Eq;
    type TransferTx: for<'a> Deserialize<'a>
        + Serialize
        + Clone
        + std::fmt::Debug
        + BorshSerialize
        + BorshDeserialize
        + PartialEq
        + Eq;
    type BondTx: for<'a> Deserialize<'a>
        + Serialize
        + Clone
        + std::fmt::Debug
        + BorshSerialize
        + BorshDeserialize
        + PartialEq
        + Eq;
}
impl TemplateValidation for Unvalidated {
    type Balances = UndenominatedBalances;
    type BondTx = SignedBondTx;
    type TransferTx = SignedTransferTx;
}
impl TemplateValidation for Validated {
    type Balances = DenominatedBalances;
    type BondTx = BondTx<Validated>;
    type TransferTx = TransferTx<Validated>;
}

#[derive(
    Clone,
    Debug,
    Deserialize,
    Serialize,
    BorshDeserialize,
    BorshSerialize,
    PartialEq,
    Eq,
)]
pub struct All<T: TemplateValidation> {
    pub vps: ValidityPredicates,
    pub tokens: Tokens,
    pub balances: T::Balances,
    pub parameters: Parameters,
    pub transactions: Transactions<T>,
}

impl<T: TemplateValidation> All<T> {
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
}

impl All<Unvalidated> {
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
pub fn load_and_validate(templates_dir: &Path) -> Option<All<Validated>> {
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

    let balances = if let Some(tokens) = tokens.as_ref() {
        if tokens.token.is_empty() {
            is_valid = false;
            eprintln!(
                "Tokens file is invalid. There has to be at least one token."
            );
        }
        println!("Tokens file is valid.");
        balances
            .and_then(|raw| raw.denominate(tokens).ok())
            .and_then(|balances| {
                validate_balances(&balances, Some(tokens)).then(|| {
                    println!("Balances file is valid.");
                    balances
                })
            })
    } else {
        None
    };
    if balances.is_none() {
        is_valid = false;
    }

    if let Some(parameters) = parameters.as_ref() {
        if validate_parameters(parameters, vps.as_ref()) {
            println!("Parameters file is valid.");
        } else {
            is_valid = false;
        }
    }

    let txs = if let Some(tokens) = tokens.as_ref() {
        if let Some(txs) = transactions.and_then(|txs| {
            transactions::validate(
                txs,
                vps.as_ref(),
                balances.as_ref(),
                tokens,
                parameters.as_ref(),
            )
        }) {
            println!("Transactions file is valid.");
            Some(txs)
        } else {
            is_valid = false;
            None
        }
    } else {
        is_valid = false;
        None
    };

    match vps {
        Some(vps) if is_valid => Some(All {
            vps,
            tokens: tokens.unwrap(),
            balances: balances.unwrap(),
            parameters: parameters.unwrap(),
            transactions: txs.unwrap(),
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

pub fn validate_balances(
    balances: &DenominatedBalances,
    tokens: Option<&Tokens>,
) -> bool {
    let mut is_valid = true;
    use std::str::FromStr;
    let native_alias = Alias::from_str("nam").expect("Infalllible");
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
                let res = acc.checked_add(amount.amount);
                if res.as_ref().is_none() {
                    is_valid = false;
                    eprintln!(
                        "Balances for token {token} overflow `token::Amount`"
                    );
                }
                res
            },
        );
        if sum.is_none()
            || (*token == native_alias
                && sum.unwrap()
                    > Amount::from_uint(
                        MAX_TOKEN_BALANCE_SUM,
                        NATIVE_MAX_DECIMAL_PLACES,
                    )
                    .unwrap())
        {
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
		{pk} = "{}"
	    "#,
            balance.to_string_native()
        );
        fs::write(&path, contents).unwrap();

        let balances = read_balances(&path).unwrap();
        let example_balance = balances.token.get(&token_alias).unwrap();
        assert_eq!(
            balance,
            example_balance
                .0
                .get(&StringEncoded { raw: pk })
                .unwrap()
                .amount
        );
    }
}
