//! The parameters used for the chain's genesis

use std::collections::HashMap;
#[cfg(not(feature = "dev"))]
use std::path::Path;

use borsh::{BorshDeserialize, BorshSerialize};
use derivative::Derivative;
#[cfg(not(feature = "mainnet"))]
use namada::core::ledger::testnet_pow;
use namada::ledger::governance::parameters::GovParams;
use namada::ledger::parameters::EpochDuration;
use namada::ledger::pos::{GenesisValidator, PosParams};
use namada::types::address::Address;
#[cfg(not(feature = "dev"))]
use namada::types::chain::ChainId;
use namada::types::chain::ProposalBytes;
use namada::types::key::dkg_session_keys::DkgPublicKey;
use namada::types::key::*;
use namada::types::time::{DateTimeUtc, DurationSecs};
use namada::types::{storage, token};
use rust_decimal::Decimal;

/// Genesis configuration file format
pub mod genesis_config {
    use std::array::TryFromSliceError;
    use std::collections::HashMap;
    use std::convert::TryInto;
    use std::path::Path;
    use std::str::FromStr;

    use data_encoding::HEXLOWER;
    use eyre::Context;
    #[cfg(not(feature = "mainnet"))]
    use namada::core::ledger::testnet_pow;
    use namada::ledger::governance::parameters::GovParams;
    use namada::ledger::parameters::EpochDuration;
    use namada::ledger::pos::{GenesisValidator, PosParams};
    use namada::types::address::Address;
    use namada::types::chain::ProposalBytes;
    use namada::types::key::dkg_session_keys::DkgPublicKey;
    use namada::types::key::*;
    use namada::types::time::Rfc3339String;
    use namada::types::{storage, token};
    use rust_decimal::Decimal;
    use serde::{Deserialize, Serialize};
    use thiserror::Error;

    use super::{
        EstablishedAccount, Genesis, ImplicitAccount, Parameters, TokenAccount,
        Validator,
    };
    use crate::cli;

    #[derive(Clone, Debug, Deserialize, Serialize)]
    pub struct HexString(pub String);

    impl HexString {
        pub fn to_bytes(&self) -> Result<Vec<u8>, HexKeyError> {
            let bytes = HEXLOWER.decode(self.0.as_ref())?;
            Ok(bytes)
        }

        pub fn to_sha256_bytes(&self) -> Result<[u8; 32], HexKeyError> {
            let bytes = HEXLOWER.decode(self.0.as_ref())?;
            let slice = bytes.as_slice();
            let array: [u8; 32] = slice.try_into()?;
            Ok(array)
        }

        pub fn to_public_key(&self) -> Result<common::PublicKey, HexKeyError> {
            let key = common::PublicKey::from_str(&self.0)
                .map_err(HexKeyError::InvalidPublicKey)?;
            Ok(key)
        }

        pub fn to_dkg_public_key(&self) -> Result<DkgPublicKey, HexKeyError> {
            let key = DkgPublicKey::from_str(&self.0)?;
            Ok(key)
        }
    }

    #[derive(Error, Debug)]
    pub enum HexKeyError {
        #[error("Invalid hex string: {0:?}")]
        InvalidHexString(data_encoding::DecodeError),
        #[error("Invalid sha256 checksum: {0}")]
        InvalidSha256(TryFromSliceError),
        #[error("Invalid public key: {0}")]
        InvalidPublicKey(ParsePublicKeyError),
    }

    impl From<data_encoding::DecodeError> for HexKeyError {
        fn from(err: data_encoding::DecodeError) -> Self {
            Self::InvalidHexString(err)
        }
    }

    impl From<ParsePublicKeyError> for HexKeyError {
        fn from(err: ParsePublicKeyError) -> Self {
            Self::InvalidPublicKey(err)
        }
    }

    impl From<TryFromSliceError> for HexKeyError {
        fn from(err: TryFromSliceError) -> Self {
            Self::InvalidSha256(err)
        }
    }

    #[derive(Clone, Debug, Deserialize, Serialize)]
    pub struct GenesisConfig {
        // Genesis timestamp
        pub genesis_time: Rfc3339String,
        // Name of the native token - this must one of the tokens included in
        // the `token` field
        pub native_token: String,
        #[cfg(not(feature = "mainnet"))]
        /// Testnet faucet PoW difficulty - defaults to `0` when not set
        pub faucet_pow_difficulty: Option<testnet_pow::Difficulty>,
        #[cfg(not(feature = "mainnet"))]
        /// Testnet faucet withdrawal limit - defaults to 1000 NAM when not set
        pub faucet_withdrawal_limit: Option<token::Amount>,
        // Initial validator set
        pub validator: HashMap<String, ValidatorConfig>,
        // Token accounts present at genesis
        pub token: HashMap<String, TokenAccountConfig>,
        // Established accounts present at genesis
        pub established: Option<HashMap<String, EstablishedAccountConfig>>,
        // Implicit accounts present at genesis
        pub implicit: Option<HashMap<String, ImplicitAccountConfig>>,
        // Protocol parameters
        pub parameters: ParametersConfig,
        // PoS parameters
        pub pos_params: PosParamsConfig,
        // Governance parameters
        pub gov_params: GovernanceParamsConfig,
        // Wasm definitions
        pub wasm: HashMap<String, WasmConfig>,
    }

    #[derive(Clone, Debug, Deserialize, Serialize)]
    pub struct GovernanceParamsConfig {
        // Min funds to stake to submit a proposal
        // XXX: u64 doesn't work with toml-rs!
        pub min_proposal_fund: u64,
        // Maximum size of proposal in kibibytes (KiB)
        // XXX: u64 doesn't work with toml-rs!
        pub max_proposal_code_size: u64,
        // Minimum proposal period length in epochs
        // XXX: u64 doesn't work with toml-rs!
        pub min_proposal_period: u64,
        // Maximum proposal period length in epochs
        // XXX: u64 doesn't work with toml-rs!
        pub max_proposal_period: u64,
        // Maximum number of characters in the proposal content
        // XXX: u64 doesn't work with toml-rs!
        pub max_proposal_content_size: u64,
        // Minimum number of epoch between end and grace epoch
        // XXX: u64 doesn't work with toml-rs!
        pub min_proposal_grace_epochs: u64,
    }

    /// Validator pre-genesis configuration can be created with client utils
    /// `init-genesis-validator` command and added to a genesis for
    /// `init-network` cmd and that can be subsequently read by `join-network`
    /// cmd to setup a genesis validator node.
    #[derive(Serialize, Deserialize, Debug)]
    pub struct ValidatorPreGenesisConfig {
        pub validator: HashMap<String, ValidatorConfig>,
    }

    #[derive(Clone, Default, Debug, Deserialize, Serialize)]
    pub struct ValidatorConfig {
        // Public key for consensus. (default: generate)
        pub consensus_public_key: Option<HexString>,
        // Public key for validator account. (default: generate)
        pub account_public_key: Option<HexString>,
        // Public protocol signing key for validator account. (default:
        // generate)
        pub protocol_public_key: Option<HexString>,
        // Public DKG session key for validator account. (default: generate)
        pub dkg_public_key: Option<HexString>,
        // Validator address (default: generate).
        pub address: Option<String>,
        // Total number of tokens held at genesis.
        // XXX: u64 doesn't work with toml-rs!
        pub tokens: Option<u64>,
        // Unstaked balance at genesis.
        // XXX: u64 doesn't work with toml-rs!
        pub non_staked_balance: Option<u64>,
        /// Commission rate charged on rewards for delegators (bounded inside
        /// 0-1)
        pub commission_rate: Option<Decimal>,
        /// Maximum change in commission rate permitted per epoch
        pub max_commission_rate_change: Option<Decimal>,
        // Filename of validator VP. (default: default validator VP)
        pub validator_vp: Option<String>,
        // IP:port of the validator. (used in generation only)
        pub net_address: Option<String>,
        /// Tendermint node key is used to derive Tendermint node ID for node
        /// authentication
        pub tendermint_node_key: Option<HexString>,
    }

    #[derive(Clone, Debug, Deserialize, Serialize)]
    pub struct TokenAccountConfig {
        // Address of token account (default: generate).
        pub address: Option<String>,
        // Filename of token account VP. (default: token VP)
        pub vp: Option<String>,
        // Initial balances held by accounts defined elsewhere.
        // XXX: u64 doesn't work with toml-rs!
        pub balances: Option<HashMap<String, u64>>,
        // Token parameters
        // XXX: u64 doesn't work with toml-rs!
        pub parameters: Option<token::parameters::Parameters>,
    }

    #[derive(Clone, Debug, Deserialize, Serialize)]
    pub struct EstablishedAccountConfig {
        // Address of established account (default: generate).
        pub address: Option<String>,
        // Filename of established account VP. (default: user VP)
        pub vp: Option<String>,
        // Public key of established account. (default: generate)
        pub public_key: Option<HexString>,
        // Initial storage key values.
        pub storage: Option<HashMap<String, HexString>>,
    }

    #[derive(Clone, Debug, Deserialize, Serialize)]
    pub struct ImplicitAccountConfig {
        // Public key of implicit account (default: generate).
        pub public_key: Option<HexString>,
    }

    #[derive(Clone, Debug, Deserialize, Serialize)]
    pub struct ParametersConfig {
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
        /// Minimum number of blocks per epoch.
        // XXX: u64 doesn't work with toml-rs!
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
        #[cfg(not(feature = "mainnet"))]
        /// Fix wrapper tx fees
        pub wrapper_tx_fees: Option<token::Amount>,
    }

    #[derive(Clone, Debug, Deserialize, Serialize)]
    pub struct PosParamsConfig {
        // Maximum number of consensus validators.
        // XXX: u64 doesn't work with toml-rs!
        pub max_validator_slots: u64,
        // Pipeline length (in epochs).
        // XXX: u64 doesn't work with toml-rs!
        pub pipeline_len: u64,
        // Unbonding length (in epochs).
        // XXX: u64 doesn't work with toml-rs!
        pub unbonding_len: u64,
        // Votes per token.
        // XXX: u64 doesn't work with toml-rs!
        pub tm_votes_per_token: Decimal,
        // Reward for proposing a block.
        // XXX: u64 doesn't work with toml-rs!
        pub block_proposer_reward: Decimal,
        // Reward for voting on a block.
        // XXX: u64 doesn't work with toml-rs!
        pub block_vote_reward: Decimal,
        // Maximum staking APY
        // XXX: u64 doesn't work with toml-rs!
        pub max_inflation_rate: Decimal,
        // Target ratio of staked NAM tokens to total NAM tokens
        pub target_staked_ratio: Decimal,
        // Portion of a validator's stake that should be slashed on a
        // duplicate vote.
        // XXX: u64 doesn't work with toml-rs!
        pub duplicate_vote_min_slash_rate: Decimal,
        // Portion of a validator's stake that should be slashed on a
        // light client attack.
        // XXX: u64 doesn't work with toml-rs!
        pub light_client_attack_min_slash_rate: Decimal,
    }

    #[derive(Clone, Debug, Deserialize, Serialize)]
    pub struct WasmConfig {
        filename: String,
        pub sha256: Option<HexString>,
    }

    fn load_validator(
        config: &ValidatorConfig,
        wasm: &HashMap<String, WasmConfig>,
    ) -> Validator {
        let validator_vp_name = config.validator_vp.as_ref().unwrap();
        let validator_vp_config = wasm.get(validator_vp_name).unwrap();

        Validator {
            pos_data: GenesisValidator {
                address: Address::decode(config.address.as_ref().unwrap())
                    .unwrap(),
                tokens: token::Amount::whole(config.tokens.unwrap_or_default()),
                consensus_key: config
                    .consensus_public_key
                    .as_ref()
                    .unwrap()
                    .to_public_key()
                    .unwrap(),
                commission_rate: config
                    .commission_rate
                    .and_then(|rate| {
                        if rate >= Decimal::ZERO && rate <= Decimal::ONE {
                            Some(rate)
                        } else {
                            None
                        }
                    })
                    .expect("Commission rate must be between 0.0 and 1.0"),
                max_commission_rate_change: config
                    .max_commission_rate_change
                    .and_then(|rate| {
                        if rate >= Decimal::ZERO && rate <= Decimal::ONE {
                            Some(rate)
                        } else {
                            None
                        }
                    })
                    .expect(
                        "Max commission rate change must be between 0.0 and \
                         1.0",
                    ),
            },
            account_key: config
                .account_public_key
                .as_ref()
                .unwrap()
                .to_public_key()
                .unwrap(),
            protocol_key: config
                .protocol_public_key
                .as_ref()
                .unwrap()
                .to_public_key()
                .unwrap(),
            dkg_public_key: config
                .dkg_public_key
                .as_ref()
                .unwrap()
                .to_dkg_public_key()
                .unwrap(),
            non_staked_balance: token::Amount::whole(
                config.non_staked_balance.unwrap_or_default(),
            ),
            validator_vp_code_path: validator_vp_config.filename.to_owned(),
            validator_vp_sha256: validator_vp_config
                .sha256
                .clone()
                .unwrap()
                .to_sha256_bytes()
                .unwrap(),
        }
    }

    fn load_token(
        config: &TokenAccountConfig,
        wasm: &HashMap<String, WasmConfig>,
        validators: &HashMap<String, Validator>,
        established_accounts: &HashMap<String, EstablishedAccount>,
        implicit_accounts: &HashMap<String, ImplicitAccount>,
    ) -> TokenAccount {
        let token_vp_name = config.vp.as_ref().unwrap();
        let token_vp_config = wasm.get(token_vp_name).unwrap();

        TokenAccount {
            last_locked_ratio: Decimal::ZERO,
            last_inflation: 0,
            parameters: config.parameters.as_ref().unwrap().to_owned(),
            address: Address::decode(config.address.as_ref().unwrap()).unwrap(),
            vp_code_path: token_vp_config.filename.to_owned(),
            vp_sha256: token_vp_config
                .sha256
                .clone()
                .unwrap_or_else(|| {
                    eprintln!("Unknown token VP WASM sha256");
                    cli::safe_exit(1);
                })
                .to_sha256_bytes()
                .unwrap(),
            balances: config
                .balances
                .as_ref()
                .unwrap_or(&HashMap::default())
                .iter()
                .map(|(alias_or_address, amount)| {
                    (
                        match Address::decode(alias_or_address) {
                            Ok(address) => address,
                            Err(decode_err) => {
                                if let Some(alias) =
                                    alias_or_address.strip_suffix(".public_key")
                                {
                                    if let Some(established) =
                                        established_accounts.get(alias)
                                    {
                                        established
                                            .public_key
                                            .as_ref()
                                            .unwrap()
                                            .into()
                                    } else if let Some(validator) =
                                        validators.get(alias)
                                    {
                                        (&validator.account_key).into()
                                    } else {
                                        eprintln!(
                                            "No established or validator \
                                             account with alias {} found",
                                            alias
                                        );
                                        cli::safe_exit(1)
                                    }
                                } else if let Some(established) =
                                    established_accounts.get(alias_or_address)
                                {
                                    established.address.clone()
                                } else if let Some(validator) =
                                    validators.get(alias_or_address)
                                {
                                    validator.pos_data.address.clone()
                                } else if let Some(implicit) =
                                    implicit_accounts.get(alias_or_address)
                                {
                                    (&implicit.public_key).into()
                                } else {
                                    eprintln!(
                                        "{} is unknown alias and not a valid \
                                         address: {}",
                                        alias_or_address, decode_err
                                    );
                                    cli::safe_exit(1)
                                }
                            }
                        },
                        token::Amount::whole(*amount),
                    )
                })
                .collect(),
        }
    }

    fn load_established(
        config: &EstablishedAccountConfig,
        wasm: &HashMap<String, WasmConfig>,
    ) -> EstablishedAccount {
        let account_vp_name = config.vp.as_ref().unwrap();
        let account_vp_config = wasm.get(account_vp_name).unwrap();

        EstablishedAccount {
            address: Address::decode(config.address.as_ref().unwrap()).unwrap(),
            vp_code_path: account_vp_config.filename.to_owned(),
            vp_sha256: account_vp_config
                .sha256
                .clone()
                .unwrap_or_else(|| {
                    eprintln!("Unknown user VP WASM sha256");
                    cli::safe_exit(1);
                })
                .to_sha256_bytes()
                .unwrap(),
            public_key: config
                .public_key
                .as_ref()
                .map(|hex| hex.to_public_key().unwrap()),
            storage: config
                .storage
                .as_ref()
                .unwrap_or(&HashMap::default())
                .iter()
                .map(|(address, hex)| {
                    (
                        storage::Key::parse(address).unwrap(),
                        hex.to_bytes().unwrap(),
                    )
                })
                .collect(),
        }
    }

    fn load_implicit(config: &ImplicitAccountConfig) -> ImplicitAccount {
        ImplicitAccount {
            public_key: config
                .public_key
                .as_ref()
                .unwrap()
                .to_public_key()
                .unwrap(),
        }
    }

    pub fn load_genesis_config(config: GenesisConfig) -> Genesis {
        let GenesisConfig {
            genesis_time,
            native_token,
            #[cfg(not(feature = "mainnet"))]
            faucet_pow_difficulty,
            #[cfg(not(feature = "mainnet"))]
            faucet_withdrawal_limit,
            validator,
            token,
            established,
            implicit,
            parameters,
            pos_params,
            gov_params,
            wasm,
        } = config;

        let native_token = Address::decode(
            token
                .get(&native_token)
                .expect(
                    "Native token's alias must be present in the declared \
                     tokens",
                )
                .address
                .as_ref()
                .expect("Missing native token address"),
        )
        .expect("Invalid address");

        let validators: HashMap<String, Validator> = validator
            .iter()
            .map(|(name, cfg)| (name.clone(), load_validator(cfg, &wasm)))
            .collect();
        let established_accounts: HashMap<String, EstablishedAccount> =
            established
                .unwrap_or_default()
                .iter()
                .map(|(name, cfg)| (name.clone(), load_established(cfg, &wasm)))
                .collect();
        let implicit_accounts: HashMap<String, ImplicitAccount> = implicit
            .unwrap_or_default()
            .iter()
            .map(|(name, cfg)| (name.clone(), load_implicit(cfg)))
            .collect();
        #[allow(clippy::iter_kv_map)]
        let token_accounts = token
            .iter()
            .map(|(_name, cfg)| {
                load_token(
                    cfg,
                    &wasm,
                    &validators,
                    &established_accounts,
                    &implicit_accounts,
                )
            })
            .collect();

        let implicit_vp_config = wasm.get(&parameters.implicit_vp).unwrap();
        let implicit_vp_code_path = implicit_vp_config.filename.to_owned();
        let implicit_vp_sha256 = implicit_vp_config
            .sha256
            .clone()
            .unwrap_or_else(|| {
                eprintln!("Unknown implicit VP WASM sha256");
                cli::safe_exit(1);
            })
            .to_sha256_bytes()
            .unwrap();

        let min_duration: i64 =
            60 * 60 * 24 * 365 / (parameters.epochs_per_year as i64);
        let parameters = Parameters {
            epoch_duration: EpochDuration {
                min_num_of_blocks: parameters.min_num_of_blocks,
                min_duration: namada::types::time::Duration::seconds(
                    min_duration,
                )
                .into(),
            },
            max_expected_time_per_block:
                namada::types::time::Duration::seconds(
                    parameters.max_expected_time_per_block,
                )
                .into(),
            max_proposal_bytes: parameters.max_proposal_bytes,
            vp_whitelist: parameters.vp_whitelist.unwrap_or_default(),
            tx_whitelist: parameters.tx_whitelist.unwrap_or_default(),
            implicit_vp_code_path,
            implicit_vp_sha256,
            epochs_per_year: parameters.epochs_per_year,
            pos_gain_p: parameters.pos_gain_p,
            pos_gain_d: parameters.pos_gain_d,
            staked_ratio: Decimal::ZERO,
            pos_inflation_amount: 0,
            wrapper_tx_fees: parameters.wrapper_tx_fees,
        };

        let GovernanceParamsConfig {
            min_proposal_fund,
            max_proposal_code_size,
            min_proposal_period,
            max_proposal_content_size,
            min_proposal_grace_epochs,
            max_proposal_period,
        } = gov_params;
        let gov_params = GovParams {
            min_proposal_fund,
            max_proposal_code_size,
            min_proposal_period,
            max_proposal_content_size,
            min_proposal_grace_epochs,
            max_proposal_period,
        };

        let PosParamsConfig {
            max_validator_slots,
            pipeline_len,
            unbonding_len,
            tm_votes_per_token,
            block_proposer_reward,
            block_vote_reward,
            max_inflation_rate,
            target_staked_ratio,
            duplicate_vote_min_slash_rate,
            light_client_attack_min_slash_rate,
        } = pos_params;
        let pos_params = PosParams {
            max_validator_slots,
            pipeline_len,
            unbonding_len,
            tm_votes_per_token,
            block_proposer_reward,
            block_vote_reward,
            max_inflation_rate,
            target_staked_ratio,
            duplicate_vote_min_slash_rate,
            light_client_attack_min_slash_rate,
        };

        let mut genesis = Genesis {
            genesis_time: genesis_time.try_into().unwrap(),
            native_token,
            #[cfg(not(feature = "mainnet"))]
            faucet_pow_difficulty,
            #[cfg(not(feature = "mainnet"))]
            faucet_withdrawal_limit,
            validators: validators.into_values().collect(),
            token_accounts,
            established_accounts: established_accounts.into_values().collect(),
            implicit_accounts: implicit_accounts.into_values().collect(),
            parameters,
            pos_params,
            gov_params,
        };
        genesis.init();
        genesis
    }

    pub fn open_genesis_config(
        path: impl AsRef<Path>,
    ) -> color_eyre::eyre::Result<GenesisConfig> {
        let config_file =
            std::fs::read_to_string(&path).wrap_err_with(|| {
                format!(
                    "couldn't read genesis config file from {}",
                    path.as_ref().to_string_lossy()
                )
            })?;
        toml::from_str(&config_file).wrap_err_with(|| {
            format!(
                "couldn't parse TOML from {}",
                path.as_ref().to_string_lossy()
            )
        })
    }

    pub fn write_genesis_config(
        config: &GenesisConfig,
        path: impl AsRef<Path>,
    ) {
        let toml = toml::to_string(&config).unwrap();
        std::fs::write(path, toml).unwrap();
    }

    pub fn read_genesis_config(path: impl AsRef<Path>) -> Genesis {
        load_genesis_config(open_genesis_config(path).unwrap())
    }
}

#[derive(Debug, BorshSerialize, BorshDeserialize)]
#[borsh_init(init)]
pub struct Genesis {
    pub genesis_time: DateTimeUtc,
    pub native_token: Address,
    #[cfg(not(feature = "mainnet"))]
    pub faucet_pow_difficulty: Option<testnet_pow::Difficulty>,
    #[cfg(not(feature = "mainnet"))]
    pub faucet_withdrawal_limit: Option<token::Amount>,
    pub validators: Vec<Validator>,
    pub token_accounts: Vec<TokenAccount>,
    pub established_accounts: Vec<EstablishedAccount>,
    pub implicit_accounts: Vec<ImplicitAccount>,
    pub parameters: Parameters,
    pub pos_params: PosParams,
    pub gov_params: GovParams,
}

impl Genesis {
    /// Sort all fields for deterministic encoding
    pub fn init(&mut self) {
        self.validators.sort();
        self.token_accounts.sort();
        self.established_accounts.sort();
        self.implicit_accounts.sort();
    }
}

#[derive(
    Clone,
    Debug,
    BorshSerialize,
    BorshDeserialize,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
)]
/// Genesis validator definition
pub struct Validator {
    /// Data that is used for PoS system initialization
    pub pos_data: GenesisValidator,
    /// Public key associated with the validator account. The default validator
    /// VP will check authorization of transactions from this account against
    /// this key on a transaction signature.
    /// Note that this is distinct from consensus key used in the PoS system.
    pub account_key: common::PublicKey,
    /// Public key associated with validator account used for signing protocol
    /// transactions
    pub protocol_key: common::PublicKey,
    /// The public DKG session key used during the DKG protocol
    pub dkg_public_key: DkgPublicKey,
    /// These tokens are not staked and hence do not contribute to the
    /// validator's voting power
    pub non_staked_balance: token::Amount,
    /// Validity predicate code WASM
    pub validator_vp_code_path: String,
    /// Expected SHA-256 hash of the validator VP
    pub validator_vp_sha256: [u8; 32],
}

#[derive(
    Clone, Debug, BorshSerialize, BorshDeserialize, PartialEq, Eq, Derivative,
)]
#[derivative(PartialOrd, Ord)]
pub struct EstablishedAccount {
    /// Address
    pub address: Address,
    /// Validity predicate code WASM
    pub vp_code_path: String,
    /// Expected SHA-256 hash of the validity predicate wasm
    pub vp_sha256: [u8; 32],
    /// A public key to be stored in the account's storage, if any
    pub public_key: Option<common::PublicKey>,
    /// Account's sub-space storage. The values must be borsh encoded bytes.
    #[derivative(PartialOrd = "ignore", Ord = "ignore")]
    pub storage: HashMap<storage::Key, Vec<u8>>,
}

#[derive(
    Clone, Debug, BorshSerialize, BorshDeserialize, PartialEq, Eq, Derivative,
)]
#[derivative(PartialOrd, Ord)]
pub struct TokenAccount {
    /// Address
    pub address: Address,
    /// Validity predicate code WASM
    pub vp_code_path: String,
    /// Expected SHA-256 hash of the validity predicate wasm
    pub vp_sha256: [u8; 32],
    /// Accounts' balances of this token
    #[derivative(PartialOrd = "ignore", Ord = "ignore")]
    pub balances: HashMap<Address, token::Amount>,
    // please put the last inflation amount here.
    /// Token parameters
    pub parameters: token::parameters::Parameters,
    /// Token inflation from the last epoch (read + write for every epoch)
    pub last_inflation: u64,
    /// Token shielded ratio from the last epoch (read + write for every epoch)
    pub last_locked_ratio: Decimal,
}

#[derive(
    Clone,
    Debug,
    BorshSerialize,
    BorshDeserialize,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
)]
pub struct ImplicitAccount {
    /// A public key from which the implicit account is derived. This will be
    /// stored on chain for the account.
    pub public_key: common::PublicKey,
}

/// Protocol parameters. This is almost the same as
/// `ledger::parameters::Parameters`, but instead of having the `implicit_vp`
/// WASM code bytes, it only has the name and sha as the actual code is loaded
/// on `init_chain`
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    BorshSerialize,
    BorshDeserialize,
)]
pub struct Parameters {
    // Max payload size, in bytes, for a tx batch proposal.
    pub max_proposal_bytes: ProposalBytes,
    /// Epoch duration
    pub epoch_duration: EpochDuration,
    /// Maximum expected time per block
    pub max_expected_time_per_block: DurationSecs,
    /// Whitelisted validity predicate hashes
    pub vp_whitelist: Vec<String>,
    /// Whitelisted tx hashes
    pub tx_whitelist: Vec<String>,
    /// Implicit accounts validity predicate code WASM
    pub implicit_vp_code_path: String,
    /// Expected SHA-256 hash of the implicit VP
    pub implicit_vp_sha256: [u8; 32],
    /// Expected number of epochs per year (read only)
    pub epochs_per_year: u64,
    /// PoS gain p (read only)
    pub pos_gain_p: Decimal,
    /// PoS gain d (read only)
    pub pos_gain_d: Decimal,
    /// PoS staked ratio (read + write for every epoch)
    pub staked_ratio: Decimal,
    /// PoS inflation amount from the last epoch (read + write for every epoch)
    pub pos_inflation_amount: u64,
    /// Fixed Wrapper tx fees
    #[cfg(not(feature = "mainnet"))]
    pub wrapper_tx_fees: Option<token::Amount>,
}

#[cfg(not(feature = "dev"))]
pub fn genesis(base_dir: impl AsRef<Path>, chain_id: &ChainId) -> Genesis {
    let path = base_dir
        .as_ref()
        .join(format!("{}.toml", chain_id.as_str()));
    genesis_config::read_genesis_config(path)
}
#[cfg(feature = "dev")]
pub fn genesis(num_validators: u64) -> Genesis {
    use namada::types::address;
    use rust_decimal_macros::dec;

    use crate::wallet;

    let vp_implicit_path = "vp_implicit.wasm";
    let vp_token_path = "vp_token.wasm";
    let vp_user_path = "vp_user.wasm";

    // NOTE When the validator's key changes, tendermint must be reset with
    // `namada reset` command. To generate a new validator, use the
    // `tests::gen_genesis_validator` below.
    let mut validators = Vec::<Validator>::new();

    // Use hard-coded keys for the first validator to avoid breaking other code
    let consensus_keypair = wallet::defaults::validator_keypair();
    let account_keypair = wallet::defaults::validator_keypair();
    let address = wallet::defaults::validator_address();
    let (protocol_keypair, dkg_keypair) = wallet::defaults::validator_keys();
    let validator = Validator {
        pos_data: GenesisValidator {
            address,
            tokens: token::Amount::whole(200_000),
            consensus_key: consensus_keypair.ref_to(),
            commission_rate: dec!(0.05),
            max_commission_rate_change: dec!(0.01),
        },
        account_key: account_keypair.ref_to(),
        protocol_key: protocol_keypair.ref_to(),
        dkg_public_key: dkg_keypair.public(),
        non_staked_balance: token::Amount::whole(100_000),
        // TODO replace with https://github.com/anoma/namada/issues/25)
        validator_vp_code_path: vp_user_path.into(),
        validator_vp_sha256: Default::default(),
    };
    validators.push(validator);

    // Add other validators with randomly generated keys if needed
    for _ in 0..(num_validators - 1) {
        let consensus_keypair: common::SecretKey =
            testing::gen_keypair::<ed25519::SigScheme>()
                .try_to_sk()
                .unwrap();
        let account_keypair = consensus_keypair.clone();
        let address = address::gen_established_address("validator account");
        let (protocol_keypair, dkg_keypair) =
            wallet::defaults::validator_keys();
        let validator = Validator {
            pos_data: GenesisValidator {
                address,
                tokens: token::Amount::whole(200_000),
                consensus_key: consensus_keypair.ref_to(),
                commission_rate: dec!(0.05),
                max_commission_rate_change: dec!(0.01),
            },
            account_key: account_keypair.ref_to(),
            protocol_key: protocol_keypair.ref_to(),
            dkg_public_key: dkg_keypair.public(),
            non_staked_balance: token::Amount::whole(100_000),
            // TODO replace with https://github.com/anoma/namada/issues/25)
            validator_vp_code_path: vp_user_path.into(),
            validator_vp_sha256: Default::default(),
        };
        validators.push(validator);
    }

    let parameters = Parameters {
        epoch_duration: EpochDuration {
            min_num_of_blocks: 10,
            min_duration: namada::types::time::Duration::seconds(600).into(),
        },
        max_expected_time_per_block: namada::types::time::DurationSecs(30),
        max_proposal_bytes: Default::default(),
        vp_whitelist: vec![],
        tx_whitelist: vec![],
        implicit_vp_code_path: vp_implicit_path.into(),
        implicit_vp_sha256: Default::default(),
        epochs_per_year: 525_600, /* seconds in yr (60*60*24*365) div seconds
                                   * per epoch (60 = min_duration) */
        pos_gain_p: dec!(0.1),
        pos_gain_d: dec!(0.1),
        staked_ratio: dec!(0.0),
        pos_inflation_amount: 0,
        wrapper_tx_fees: Some(token::Amount::whole(0)),
    };
    let albert = EstablishedAccount {
        address: wallet::defaults::albert_address(),
        vp_code_path: vp_user_path.into(),
        vp_sha256: Default::default(),
        public_key: Some(wallet::defaults::albert_keypair().ref_to()),
        storage: HashMap::default(),
    };
    let bertha = EstablishedAccount {
        address: wallet::defaults::bertha_address(),
        vp_code_path: vp_user_path.into(),
        vp_sha256: Default::default(),
        public_key: Some(wallet::defaults::bertha_keypair().ref_to()),
        storage: HashMap::default(),
    };
    let christel = EstablishedAccount {
        address: wallet::defaults::christel_address(),
        vp_code_path: vp_user_path.into(),
        vp_sha256: Default::default(),
        public_key: Some(wallet::defaults::christel_keypair().ref_to()),
        storage: HashMap::default(),
    };
    let masp = EstablishedAccount {
        address: namada::types::address::masp(),
        vp_code_path: "vp_masp.wasm".into(),
        vp_sha256: Default::default(),
        public_key: None,
        storage: HashMap::default(),
    };
    let implicit_accounts = vec![ImplicitAccount {
        public_key: wallet::defaults::daewon_keypair().ref_to(),
    }];
    let default_user_tokens = token::Amount::whole(1_000_000);
    let default_key_tokens = token::Amount::whole(1_000);
    let mut balances: HashMap<Address, token::Amount> = HashMap::from_iter([
        // established accounts' balances
        (wallet::defaults::albert_address(), default_user_tokens),
        (wallet::defaults::bertha_address(), default_user_tokens),
        (wallet::defaults::christel_address(), default_user_tokens),
        // implicit accounts' balances
        (wallet::defaults::daewon_address(), default_user_tokens),
        // implicit accounts derived from public keys balances
        (
            bertha.public_key.as_ref().unwrap().into(),
            default_key_tokens,
        ),
        (
            albert.public_key.as_ref().unwrap().into(),
            default_key_tokens,
        ),
        (
            christel.public_key.as_ref().unwrap().into(),
            default_key_tokens,
        ),
    ]);
    for validator in &validators {
        balances.insert((&validator.account_key).into(), default_key_tokens);
    }

    let token_accounts = address::tokens()
        .into_keys()
        .map(|address| TokenAccount {
            address,
            vp_code_path: vp_token_path.into(),
            vp_sha256: Default::default(),
            balances: balances.clone(),
            parameters: token::parameters::Parameters::default(),
            last_inflation: 0,
            last_locked_ratio: Decimal::ZERO,
        })
        .collect();
    Genesis {
        genesis_time: DateTimeUtc::now(),
        validators,
        established_accounts: vec![albert, bertha, christel, masp],
        implicit_accounts,
        token_accounts,
        parameters,
        pos_params: PosParams::default(),
        gov_params: GovParams::default(),
        native_token: address::nam(),
        #[cfg(not(feature = "mainnet"))]
        faucet_pow_difficulty: None,
        #[cfg(not(feature = "mainnet"))]
        faucet_withdrawal_limit: None,
    }
}

#[cfg(test)]
pub mod tests {
    use borsh::BorshSerialize;
    use namada::types::address::testing::gen_established_address;
    use namada::types::key::*;
    use rand::prelude::ThreadRng;
    use rand::thread_rng;

    use crate::wallet;

    /// Run `cargo test gen_genesis_validator -- --nocapture` to generate a
    /// new genesis validator address and keypair.
    #[test]
    fn gen_genesis_validator() {
        let address = gen_established_address();
        let mut rng: ThreadRng = thread_rng();
        let keypair: common::SecretKey =
            ed25519::SigScheme::generate(&mut rng).try_to_sk().unwrap();
        let kp_arr = keypair.try_to_vec().unwrap();
        let (protocol_keypair, dkg_keypair) =
            wallet::defaults::validator_keys();
        println!("address: {}", address);
        println!("keypair: {:?}", kp_arr);
        println!("protocol_keypair: {:?}", protocol_keypair);
        println!("dkg_keypair: {:?}", dkg_keypair.try_to_vec().unwrap());
    }
}
