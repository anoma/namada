//! The parameters used for the chain's genesis

pub mod chain;
pub mod templates;
pub mod toml_utils;
pub mod transactions;

use std::collections::HashMap;

use borsh::{BorshDeserialize, BorshSerialize};
use derivative::Derivative;
#[cfg(not(feature = "mainnet"))]
use namada::core::ledger::testnet_pow;
use namada::ledger::eth_bridge::EthereumBridgeParams;
use namada::ledger::governance::parameters::GovParams;
use namada::ledger::parameters::EpochDuration;
use namada::ledger::pos::{Dec, GenesisValidator, PosParams};
use namada::types::address::Address;
use namada::types::chain::ProposalBytes;
use namada::types::key::dkg_session_keys::DkgPublicKey;
use namada::types::key::*;
use namada::types::time::{DateTimeUtc, DurationSecs};
use namada::types::token::Denomination;
use namada::types::uint::Uint;
use namada::types::{storage, token};

#[cfg(test)]
use crate::config::genesis::chain::Finalized;

/// Genesis configuration file format
pub mod genesis_config {
    use std::array::TryFromSliceError;
    use std::collections::HashMap;
    use std::convert::TryInto;
    use std::path::Path;
    use std::str::FromStr;

    use data_encoding::HEXLOWER;
    #[cfg(not(feature = "mainnet"))]
    use namada::core::ledger::testnet_pow;
    use namada::ledger::pos::Dec;
    use namada::types::chain::ProposalBytes;
    use namada::types::key::dkg_session_keys::DkgPublicKey;
    use namada::types::key::*;
    use namada::types::time::Rfc3339String;
    use namada::types::token::{self, Denomination};
    use namada::types::uint::Uint;
    use serde::{Deserialize, Serialize};
    use thiserror::Error;

    use super::{
        EstablishedAccount, EthereumBridgeParams, Genesis, ImplicitAccount,
        TokenAccount, Validator,
    };

    macro_rules! to_remove {
        () => {
            todo!()
        };
    }

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
        InvalidHexString(#[from] data_encoding::DecodeError),
        #[error("Invalid sha256 checksum: {0}")]
        InvalidSha256(#[from] TryFromSliceError),
        #[error("Invalid public key: {0}")]
        InvalidPublicKey(#[from] common::DecodeError),
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
        /// Testnet faucet withdrawal limit - defaults to 1000 tokens when not
        /// set
        pub faucet_withdrawal_limit: Option<Uint>,
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
        // Ethereum bridge config
        pub ethereum_bridge_params: Option<EthereumBridgeParams>,
        // Wasm definitions
        pub wasm: HashMap<String, WasmConfig>,
    }

    #[derive(Clone, Debug, Deserialize, Serialize)]
    pub struct GovernanceParamsConfig {
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
        // Public key (cold) for eth governance. (default: generate)
        pub eth_cold_key: Option<HexString>,
        // Public key (hot) for eth bridge. (default: generate)
        pub eth_hot_key: Option<HexString>,
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
        pub tokens: Option<u64>,
        // Unstaked balance at genesis.
        pub non_staked_balance: Option<u64>,
        /// Commission rate charged on rewards for delegators (bounded inside
        /// 0-1)
        pub commission_rate: Option<Dec>,
        /// Maximum change in commission rate permitted per epoch
        pub max_commission_rate_change: Option<Dec>,
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
        // The number of decimal places amounts of this token has
        pub denom: Denomination,
        // Filename of token account VP. (default: token VP)
        pub vp: Option<String>,
        // Initial balances held by accounts defined elsewhere.
        pub balances: Option<HashMap<String, token::Amount>>,
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
        pub pos_gain_p: Dec,
        /// PoS gain d
        pub pos_gain_d: Dec,
        #[cfg(not(feature = "mainnet"))]
        /// Fix wrapper tx fees
        pub wrapper_tx_fees: Option<token::Amount>,
    }

    #[derive(Clone, Debug, Deserialize, Serialize)]
    pub struct PosParamsConfig {
        // Maximum number of consensus validators.
        pub max_validator_slots: u64,
        // Pipeline length (in epochs).
        pub pipeline_len: u64,
        // Unbonding length (in epochs).
        pub unbonding_len: u64,
        // Votes per token.
        pub tm_votes_per_token: Dec,
        // Reward for proposing a block.
        pub block_proposer_reward: Dec,
        // Reward for voting on a block.
        pub block_vote_reward: Dec,
        // Maximum staking APY
        pub max_inflation_rate: Dec,
        // Target ratio of staked NAM tokens to total NAM tokens
        pub target_staked_ratio: Dec,
        // Portion of a validator's stake that should be slashed on a
        // duplicate vote.
        pub duplicate_vote_min_slash_rate: Dec,
        // Portion of a validator's stake that should be slashed on a
        // light client attack.
        pub light_client_attack_min_slash_rate: Dec,
        /// Number of epochs above and below (separately) the current epoch to
        /// consider when doing cubic slashing
        pub cubic_slashing_window_length: u64,
        /// The minimum amount of bonded tokens that a validator needs to be in
        /// either the `consensus` or `below_capacity` validator sets
        pub validator_stake_threshold: token::Amount,
    }

    #[derive(Clone, Debug, Deserialize, Serialize)]
    pub struct WasmConfig {
        filename: String,
        pub sha256: Option<HexString>,
    }

    #[allow(dead_code)]
    fn load_validator(
        _: &ValidatorConfig,
        _: &HashMap<String, WasmConfig>,
    ) -> Validator {
        to_remove!()
    }

    #[allow(dead_code)]
    fn load_token(
        _config: &TokenAccountConfig,
        _validators: &HashMap<String, Validator>,
        _established_accounts: &HashMap<String, EstablishedAccount>,
        _implicit_accounts: &HashMap<String, ImplicitAccount>,
    ) -> TokenAccount {
        to_remove!()
    }

    #[allow(dead_code)]
    fn load_established(
        _config: &EstablishedAccountConfig,
        _wasm: &HashMap<String, WasmConfig>,
    ) -> EstablishedAccount {
        to_remove!()
    }

    #[allow(dead_code)]
    fn load_implicit(_config: &ImplicitAccountConfig) -> ImplicitAccount {
        to_remove!()
    }

    #[allow(dead_code)]
    pub fn load_genesis_config(_config: GenesisConfig) -> Genesis {
        to_remove!()
    }

    #[allow(dead_code)]
    pub fn open_genesis_config(
        _path: impl AsRef<Path>,
    ) -> color_eyre::eyre::Result<GenesisConfig> {
        to_remove!()
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
    pub faucet_withdrawal_limit: Option<Uint>,
    pub validators: Vec<Validator>,
    pub token_accounts: Vec<TokenAccount>,
    pub established_accounts: Vec<EstablishedAccount>,
    pub implicit_accounts: Vec<ImplicitAccount>,
    pub parameters: Parameters,
    pub pos_params: PosParams,
    pub gov_params: GovParams,
    // Ethereum bridge config
    pub ethereum_bridge_params: Option<EthereumBridgeParams>,
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
    /// The number of decimal places amounts of this token has
    pub denom: Denomination,
    /// Accounts' balances of this token
    #[derivative(PartialOrd = "ignore", Ord = "ignore")]
    pub balances: HashMap<Address, token::Amount>,
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
    pub pos_gain_p: Dec,
    /// PoS gain d (read only)
    pub pos_gain_d: Dec,
    /// PoS staked ratio (read + write for every epoch)
    pub staked_ratio: Dec,
    /// PoS inflation amount from the last epoch (read + write for every epoch)
    pub pos_inflation_amount: token::Amount,
    /// Fixed Wrapper tx fees
    #[cfg(not(feature = "mainnet"))]
    pub wrapper_tx_fees: Option<token::Amount>,
}

/// Modify the default genesis file (namada/genesis/localnet/) to
/// accommodate testing.
///
/// This includes adding the Ethereum bridge parameters and
/// adding a specified number of validators.
#[cfg(test)]
pub fn make_dev_genesis(num_validators: u64) -> Finalized {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::str::FromStr;
    use std::time::Duration;

    use namada::core::types::string_encoding::StringEncoded;
    use namada::ledger::eth_bridge::{Contracts, UpgradeableContract};
    use namada::ledger::wallet::alias::Alias;
    use namada::proto::{standalone_signature, SerializeWithBorsh};
    use namada::types::address::wnam;
    use namada::types::chain::ChainIdPrefix;
    use namada::types::ethereum_events::EthAddress;
    use namada::types::token::NATIVE_MAX_DECIMAL_PLACES;

    use crate::config::genesis::chain::finalize;
    use crate::wallet::defaults;

    let mut current_path = std::env::current_dir()
        .expect("Current directory should exist")
        .canonicalize()
        .expect("Current directory should exist");
    while current_path.file_name().unwrap() != "apps" {
        current_path.pop();
    }
    current_path.pop();
    let chain_dir = current_path.join("genesis").join("localnet");
    let templates = templates::load_and_validate(&chain_dir)
        .expect("Missing genesis files");
    let mut genesis = finalize(
        templates,
        ChainIdPrefix::from_str("test").unwrap(),
        DateTimeUtc::now(),
        Duration::from_secs(30).into(),
    );

    // Add Ethereum bridge params.
    genesis.parameters.eth_bridge_params = Some(templates::EthBridgeParams {
        eth_start_height: Default::default(),
        min_confirmations: Default::default(),
        contracts: Contracts {
            native_erc20: wnam(),
            bridge: UpgradeableContract {
                address: EthAddress([0; 20]),
                version: Default::default(),
            },
            governance: UpgradeableContract {
                address: EthAddress([1; 20]),
                version: Default::default(),
            },
        },
    });
    if let Some(vals) = genesis.transactions.validator_account.as_mut() {
        vals[0].address = defaults::validator_address();
    }
    let default_addresses: HashMap<Alias, Address> =
        defaults::addresses().into_iter().collect();
    if let Some(accs) = genesis.transactions.established_account.as_mut() {
        for acc in accs {
            if let Some(addr) = default_addresses.get(&acc.tx.alias) {
                acc.address = addr.clone();
            }
        }
    }
    // remove Albert's bond since it messes up existing unit test math
    if let Some(bonds) = genesis.transactions.bond.as_mut() {
        bonds.retain(|bond| {
            bond.source
                != transactions::AliasOrPk::Alias(
                    Alias::from_str("albert").unwrap(),
                )
        })
    };
    let secp_eth_cold_keypair = secp256k1::SecretKey::try_from_slice(&[
        90, 83, 107, 155, 193, 251, 120, 27, 76, 1, 188, 8, 116, 121, 90, 99,
        65, 17, 187, 6, 238, 141, 63, 188, 76, 38, 102, 7, 47, 185, 28, 52,
    ])
    .unwrap();
    let sign_pk = |sk: &common::SecretKey| transactions::SignedPk {
        pk: StringEncoded { raw: sk.ref_to() },
        authorization: StringEncoded {
            raw: standalone_signature::<_, SerializeWithBorsh>(
                sk,
                &sk.ref_to(),
            ),
        },
    };
    // Add other validators with randomly generated keys if needed
    for val in 0..(num_validators - 1) {
        let consensus_keypair: common::SecretKey =
            testing::gen_keypair::<ed25519::SigScheme>()
                .try_to_sk()
                .unwrap();
        let account_keypair = consensus_keypair.clone();
        let address = namada::types::address::gen_established_address(
            "validator account",
        );
        let eth_cold_keypair =
            common::SecretKey::try_from_sk(&secp_eth_cold_keypair).unwrap();
        let (protocol_keypair, eth_bridge_keypair, dkg_keypair) =
            defaults::validator_keys();
        let alias = Alias::from_str(&format!("validator-{}", val + 1))
            .expect("infallible");
        // add the validator
        if let Some(vals) = genesis.transactions.validator_account.as_mut() {
            vals.push(chain::FinalizedValidatorAccountTx {
                address,
                tx: transactions::ValidatorAccountTx {
                    alias: alias.clone(),
                    dkg_key: StringEncoded {
                        raw: dkg_keypair.public(),
                    },
                    vp: "vp_validator".to_string(),
                    commission_rate: Dec::new(5, 2).expect("This can't fail"),
                    max_commission_rate_change: Dec::new(1, 2)
                        .expect("This can't fail"),
                    net_address: SocketAddr::new(
                        IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
                        8080,
                    ),
                    account_key: sign_pk(&account_keypair),
                    consensus_key: sign_pk(&consensus_keypair),
                    protocol_key: sign_pk(&protocol_keypair),
                    tendermint_node_key: sign_pk(&consensus_keypair),
                    eth_hot_key: sign_pk(&eth_bridge_keypair),
                    eth_cold_key: sign_pk(&eth_cold_keypair),
                },
            })
        };
        // add the balance to validators implicit key
        if let Some(bals) = genesis
            .balances
            .token
            .get_mut(&Alias::from_str("nam").unwrap())
        {
            bals.0.insert(
                StringEncoded {
                    raw: account_keypair.ref_to(),
                },
                token::DenominatedAmount {
                    amount: token::Amount::native_whole(200_000),
                    denom: NATIVE_MAX_DECIMAL_PLACES.into(),
                },
            );
        }
        // transfer funds from implicit key to validator
        if let Some(trans) = genesis.transactions.transfer.as_mut() {
            trans.push(transactions::TransferTx {
                token: Alias::from_str("nam").expect("infallible"),
                source: StringEncoded {
                    raw: account_keypair.ref_to(),
                },
                target: alias.clone(),
                amount: token::DenominatedAmount {
                    amount: token::Amount::native_whole(200_000),
                    denom: NATIVE_MAX_DECIMAL_PLACES.into(),
                },
                valid: Default::default(),
            })
        }
        // self bond
        if let Some(bonds) = genesis.transactions.bond.as_mut() {
            bonds.push(transactions::BondTx {
                source: transactions::AliasOrPk::Alias(alias.clone()),
                validator: alias,
                amount: token::DenominatedAmount {
                    amount: token::Amount::native_whole(100_000),
                    denom: NATIVE_MAX_DECIMAL_PLACES.into(),
                },
                valid: Default::default(),
            })
        }
    }

    genesis
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
        let (protocol_keypair, _eth_hot_bridge_keypair, dkg_keypair) =
            wallet::defaults::validator_keys();

        // TODO: derive validator eth address from an eth keypair
        let eth_cold_gov_keypair: common::SecretKey =
            secp256k1::SigScheme::generate(&mut rng)
                .try_to_sk()
                .unwrap();
        let eth_hot_bridge_keypair: common::SecretKey =
            secp256k1::SigScheme::generate(&mut rng)
                .try_to_sk()
                .unwrap();

        println!("address: {}", address);
        println!("keypair: {:?}", kp_arr);
        println!("protocol_keypair: {:?}", protocol_keypair);
        println!("dkg_keypair: {:?}", dkg_keypair.try_to_vec().unwrap());
        println!(
            "eth_cold_gov_keypair: {:?}",
            eth_cold_gov_keypair.try_to_vec().unwrap()
        );
        println!(
            "eth_hot_bridge_keypair: {:?}",
            eth_hot_bridge_keypair.try_to_vec().unwrap()
        );
    }
}
