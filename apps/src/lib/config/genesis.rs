//! The parameters used for the chain's genesis

pub mod chain;
pub mod templates;
pub mod toml_utils;
pub mod transactions;

use std::array::TryFromSliceError;
use std::collections::{BTreeMap, HashMap};
use std::str::FromStr;

use borsh::{BorshDeserialize, BorshSerialize};
use data_encoding::HEXLOWER;
use derivative::Derivative;
use namada::core::ledger::governance::parameters::GovernanceParameters;
use namada::core::ledger::pgf::parameters::PgfParameters;
use namada::core::types::string_encoding;
use namada::ledger::eth_bridge::EthereumBridgeParams;
use namada::ledger::parameters::EpochDuration;
use namada::ledger::pos::{Dec, GenesisValidator, OwnedPosParams};
use namada::types::address::Address;
use namada::types::chain::ProposalBytes;
use namada::types::key::dkg_session_keys::DkgPublicKey;
use namada::types::key::*;
use namada::types::time::{DateTimeUtc, DurationSecs};
use namada::types::token::Denomination;
use namada::types::{storage, token};
use serde::{Deserialize, Serialize};

#[cfg(all(any(test, feature = "benches"), not(feature = "integration")))]
use crate::config::genesis::chain::Finalized;

#[derive(Debug, BorshSerialize, BorshDeserialize)]
#[borsh(init=init)]
pub struct Genesis {
    pub genesis_time: DateTimeUtc,
    pub native_token: Address,
    pub validators: Vec<Validator>,
    pub token_accounts: Vec<TokenAccount>,
    pub established_accounts: Vec<EstablishedAccount>,
    pub implicit_accounts: Vec<ImplicitAccount>,
    pub parameters: Parameters,
    pub pos_params: OwnedPosParams,
    pub gov_params: GovernanceParameters,
    pub pgf_params: PgfParameters,
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
    /// Token parameters
    pub parameters: token::Parameters,
    /// Token inflation from the last epoch (read + write for every epoch)
    pub last_inflation: token::Amount,
    /// Token shielded ratio from the last epoch (read + write for every epoch)
    pub last_locked_ratio: Dec,
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
    /// Max block gas
    pub max_block_gas: u64,
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
    /// Maximum amount of signatures per transaction
    pub max_signatures_per_transaction: u8,
    /// PoS gain p (read only)
    pub pos_gain_p: Dec,
    /// PoS gain d (read only)
    pub pos_gain_d: Dec,
    /// PoS staked ratio (read + write for every epoch)
    pub staked_ratio: Dec,
    /// PoS inflation amount from the last epoch (read + write for every epoch)
    pub pos_inflation_amount: token::Amount,
    /// Fee unshielding gas limit
    pub fee_unshielding_gas_limit: u64,
    /// Fee unshielding descriptions limit
    pub fee_unshielding_descriptions_limit: u64,
    /// Map of the cost per gas unit for every token allowed for fee payment
    pub minimum_gas_price: BTreeMap<Address, token::Amount>,
}

#[derive(
    Clone,
    Debug,
    Deserialize,
    Serialize,
    BorshSerialize,
    BorshDeserialize,
    PartialOrd,
    Ord,
    PartialEq,
    Eq,
)]
pub struct HexString(pub String);

impl HexString {
    pub fn parse(&self) -> Result<Vec<u8>, HexKeyError> {
        let bytes = HEXLOWER.decode(self.0.as_ref())?;
        Ok(bytes)
    }
}

#[derive(thiserror::Error, Debug)]
pub enum HexKeyError {
    #[error("Invalid hex string: {0:?}")]
    InvalidHexString(data_encoding::DecodeError),
    #[error("Invalid sha256 checksum: {0}")]
    InvalidSha256(TryFromSliceError),
    #[error("Invalid public key: {0}")]
    InvalidPublicKey(string_encoding::DecodeError),
}

impl From<data_encoding::DecodeError> for HexKeyError {
    fn from(err: data_encoding::DecodeError) -> Self {
        Self::InvalidHexString(err)
    }
}

impl From<string_encoding::DecodeError> for HexKeyError {
    fn from(err: string_encoding::DecodeError) -> Self {
        Self::InvalidPublicKey(err)
    }
}

impl From<TryFromSliceError> for HexKeyError {
    fn from(err: TryFromSliceError) -> Self {
        Self::InvalidSha256(err)
    }
}

/// Modify the default genesis file (namada/genesis/localnet/) to
/// accommodate testing.
///
/// This includes adding the Ethereum bridge parameters and
/// adding a specified number of validators.
#[cfg(all(any(test, feature = "benches"), not(feature = "integration")))]
pub fn make_dev_genesis(
    num_validators: u64,
    target_chain_dir: std::path::PathBuf,
) -> Finalized {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::time::Duration;

    use namada::core::types::string_encoding::StringEncoded;
    use namada::ledger::eth_bridge::{Contracts, UpgradeableContract};
    use namada::proto::{standalone_signature, SerializeWithBorsh};
    use namada::types::address::wnam;
    use namada::types::chain::ChainIdPrefix;
    use namada::types::ethereum_events::EthAddress;
    use namada::types::token::NATIVE_MAX_DECIMAL_PLACES;
    use namada_sdk::wallet::alias::Alias;

    use crate::config::genesis::chain::finalize;
    use crate::wallet::defaults;

    let mut current_path = std::env::current_dir()
        .expect("Current directory should exist")
        .canonicalize()
        .expect("Current directory should exist");
    // Find the project root dir
    while !current_path.join("rust-toolchain.toml").exists() {
        current_path.pop();
    }
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
        },
        erc20_whitelist: vec![],
    });

    if let Some(vals) = genesis.transactions.validator_account.as_mut() {
        vals[0].address = defaults::validator_address();
    }

    // Use the default address for matching established accounts
    let default_addresses: HashMap<Alias, Address> =
        defaults::addresses().into_iter().collect();
    if let Some(accs) = genesis.transactions.established_account.as_mut() {
        for acc in accs {
            if let Some(addr) = default_addresses.get(&acc.tx.alias) {
                acc.address = addr.clone();
            }
        }
    }

    // Use the default token address for matching tokens
    let default_tokens: HashMap<Alias, Address> = defaults::tokens()
        .into_iter()
        .map(|(address, alias)| (Alias::from(alias), address))
        .collect();
    for (alias, token) in genesis.tokens.token.iter_mut() {
        if let Some(addr) = default_tokens.get(alias) {
            token.address = addr.clone();
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
            })
        }
    }

    // Write out the TOML files for benches
    #[cfg(feature = "benches")]
    genesis
        .write_toml_files(&target_chain_dir)
        .expect("Must be able to write the finalized genesis");
    #[cfg(not(feature = "benches"))]
    let _ = target_chain_dir; // avoid unused warn

    genesis
}

#[cfg(test)]
pub mod tests {
    use borsh_ext::BorshSerializeExt;
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
        let kp_arr = keypair.serialize_to_vec();
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
        println!("dkg_keypair: {:?}", dkg_keypair.serialize_to_vec());
        println!(
            "eth_cold_gov_keypair: {:?}",
            eth_cold_gov_keypair.serialize_to_vec()
        );
        println!(
            "eth_hot_bridge_keypair: {:?}",
            eth_hot_bridge_keypair.serialize_to_vec()
        );
    }
}
