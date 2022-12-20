use std::collections::BTreeMap;
use std::path::Path;

use borsh::{BorshDeserialize, BorshSerialize};
use namada::types::address::{Address, EstablishedAddressGen};
use namada::types::chain::{ChainId, ChainIdPrefix};
use namada::types::time::{DateTimeUtc, DurationNanos, Rfc3339String};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::toml_utils::{read_toml, write_toml};
use super::{templates, transactions};
use crate::wallet::Alias;

pub const METADATA_FILE_NAME: &str = "chain.toml";

// Rng source used for generating genesis addresses. Because the process has to
// be deterministic, change of this value is a breaking change for genesis.
const ADDRESS_RNG_SOURCE: &[u8] = &[];

impl Finalized {
    /// Write all genesis and the chain metadata TOML files to the given
    /// directory.
    pub fn write_toml_files(&self, output_dir: &Path) -> eyre::Result<()> {
        let vps_file = output_dir.join(templates::VPS_FILE_NAME);
        let tokens_file = output_dir.join(templates::TOKENS_FILE_NAME);
        let balances_file = output_dir.join(templates::BALANCES_FILE_NAME);
        let parameters_file = output_dir.join(templates::PARAMETERS_FILE_NAME);
        let transactions_file =
            output_dir.join(templates::TRANSACTIONS_FILE_NAME);
        let metadata_file = output_dir.join(METADATA_FILE_NAME);

        write_toml(&self.vps, &vps_file, "Validity predicates")?;
        write_toml(&self.tokens, &tokens_file, "Tokens")?;
        write_toml(&self.balances, &balances_file, "Balances")?;
        write_toml(&self.parameters, &parameters_file, "Parameters")?;
        write_toml(&self.transactions, &transactions_file, "Transactions")?;
        write_toml(&self.metadata, &metadata_file, "Chain metadata")?;
        Ok(())
    }

    /// Try to read all genesis and the chain metadata TOML files from the given
    /// directory.
    pub fn read_toml_files(input_dir: &Path) -> eyre::Result<Self> {
        let vps_file = input_dir.join(templates::VPS_FILE_NAME);
        let tokens_file = input_dir.join(templates::TOKENS_FILE_NAME);
        let balances_file = input_dir.join(templates::BALANCES_FILE_NAME);
        let parameters_file = input_dir.join(templates::PARAMETERS_FILE_NAME);
        let transactions_file =
            input_dir.join(templates::TRANSACTIONS_FILE_NAME);
        let metadata_file = input_dir.join(METADATA_FILE_NAME);

        let vps = read_toml(&vps_file, "Validity predicates")?;
        let tokens = read_toml(&tokens_file, "Tokens")?;
        let balances = read_toml(&balances_file, "Balances")?;
        let parameters = read_toml(&parameters_file, "Parameters")?;
        let transactions = read_toml(&transactions_file, "Transactions")?;
        let metadata = read_toml(&metadata_file, "Chain metadata")?;
        Ok(Self {
            vps,
            tokens,
            balances,
            parameters,
            transactions,
            metadata,
        })
    }
}

/// Create the [`Finalized`] chain configuration. Derives the chain ID from the
/// genesis bytes and assigns addresses to tokens and transactions that
/// initialize established accounts.
///
/// Invariant: The output must deterministic. For the same input this function
/// must return the same output.
pub fn finalize(
    templates: templates::All,
    chain_id_prefix: ChainIdPrefix,
    genesis_time: DateTimeUtc,
    consensus_timeout_commit: crate::facade::tendermint::Timeout,
) -> Finalized {
    let genesis_time: Rfc3339String = genesis_time.into();
    let consensus_timeout_commit: DurationNanos =
        consensus_timeout_commit.into();

    // Derive seed for address generator
    let genesis_to_gen_address = GenesisToGenAddresses {
        templates,
        metadata: Metadata {
            chain_id: chain_id_prefix.clone(),
            genesis_time,
            consensus_timeout_commit,
            address_gen: None,
        },
    };
    let genesis_bytes = genesis_to_gen_address.try_to_vec().unwrap();
    let mut addr_gen = established_address_gen(&genesis_bytes);

    // Generate addresses
    let templates::All {
        vps,
        tokens,
        balances,
        parameters,
        transactions,
    } = genesis_to_gen_address.templates;
    let tokens = FinalizedTokens::finalize_from(tokens, &mut addr_gen);
    let transactions =
        FinalizedTransactions::finalize_from(transactions, &mut addr_gen);

    // Store the last state of the address generator in the metadata
    let mut metadata = genesis_to_gen_address.metadata;
    metadata.address_gen = Some(addr_gen);

    // Derive chain ID
    let to_finalize = ToFinalize {
        metadata,
        vps,
        tokens,
        balances,
        parameters,
        transactions,
    };
    let to_finalize_bytes = to_finalize.try_to_vec().unwrap();
    let chain_id = ChainId::from_genesis(chain_id_prefix, to_finalize_bytes);

    // Construct the `Finalized` chain
    let ToFinalize {
        vps,
        tokens,
        balances,
        parameters,
        transactions,
        metadata,
    } = to_finalize;
    let Metadata {
        chain_id: _,
        genesis_time,
        consensus_timeout_commit,
        address_gen,
    } = metadata;
    let metadata = Metadata {
        chain_id,
        genesis_time,
        consensus_timeout_commit,
        address_gen,
    };
    Finalized {
        metadata,
        vps,
        tokens,
        balances,
        parameters,
        transactions,
    }
}

/// Use bytes as a deterministic seed for address generator.
fn established_address_gen(bytes: &[u8]) -> EstablishedAddressGen {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    // hex of the first 40 chars of the hash
    let hash = format!("{:.width$X}", hasher.finalize(), width = 40);
    EstablishedAddressGen::new(&hash)
}

/// Deterministically generate an [`Address`].
fn gen_address(gen: &mut EstablishedAddressGen) -> Address {
    gen.generate_address(ADDRESS_RNG_SOURCE)
}

/// Chain genesis config to be finalized. This struct is used to derive the
/// chain ID to construct a [`Finalized`] chain genesis config.
#[derive(
    Clone, Debug, Deserialize, Serialize, BorshDeserialize, BorshSerialize,
)]
pub struct GenesisToGenAddresses {
    /// Filled-in templates
    pub templates: templates::All,
    /// Chain metadata
    pub metadata: Metadata<ChainIdPrefix>,
}

/// Chain genesis config to be finalized. This struct is used to derive the
/// chain ID to construct a [`Finalized`] chain genesis config.
pub type ToFinalize = Chain<ChainIdPrefix>;

/// Chain genesis config.
pub type Finalized = Chain<ChainId>;

/// Chain genesis config with generic chain ID.
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
pub struct Chain<ID> {
    pub vps: templates::ValidityPredicates,
    pub tokens: FinalizedTokens,
    pub balances: templates::Balances,
    pub parameters: templates::Parameters,
    pub transactions: FinalizedTransactions,
    /// Chain metadata
    pub metadata: Metadata<ID>,
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
pub struct FinalizedTokens {
    pub token: BTreeMap<Alias, FinalizedTokenConfig>,
}
impl FinalizedTokens {
    fn finalize_from(
        tokens: templates::Tokens,
        addr_gen: &mut EstablishedAddressGen,
    ) -> FinalizedTokens {
        let templates::Tokens { token } = tokens;
        let token = token
            .into_iter()
            .map(|(key, config)| {
                let address = gen_address(addr_gen);
                (key, FinalizedTokenConfig { address, config })
            })
            .collect();
        FinalizedTokens { token }
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
pub struct FinalizedTokenConfig {
    pub address: Address,
    #[serde(flatten)]
    pub config: templates::TokenConfig,
}

#[derive(
    Clone,
    Debug,
    Default,
    Deserialize,
    Serialize,
    BorshDeserialize,
    BorshSerialize,
    PartialEq,
    Eq,
)]
pub struct FinalizedTransactions {
    pub established_account: Option<Vec<FinalizedEstablishedAccountTx>>,
    pub validator_account: Option<Vec<FinalizedValidatorAccountTx>>,
    pub transfer: Option<Vec<transactions::SignedTransferTx>>,
    pub bond: Option<Vec<transactions::SignedBondTx>>,
}
impl FinalizedTransactions {
    fn finalize_from(
        transactions: transactions::Transactions,
        addr_gen: &mut EstablishedAddressGen,
    ) -> FinalizedTransactions {
        let transactions::Transactions {
            established_account,
            validator_account,
            transfer,
            bond,
        } = transactions;
        let established_account = established_account.map(|txs| {
            txs.into_iter()
                .map(|tx| {
                    let address = gen_address(addr_gen);
                    FinalizedEstablishedAccountTx { address, tx }
                })
                .collect()
        });
        let validator_account = validator_account.map(|txs| {
            txs.into_iter()
                .map(|tx| {
                    let address = gen_address(addr_gen);
                    FinalizedValidatorAccountTx { address, tx }
                })
                .collect()
        });
        FinalizedTransactions {
            established_account,
            validator_account,
            transfer,
            bond,
        }
    }
}

#[derive(
    Clone,
    Debug,
    Deserialize,
    Serialize,
    BorshSerialize,
    BorshDeserialize,
    PartialEq,
    Eq,
)]
pub struct FinalizedEstablishedAccountTx {
    pub address: Address,
    #[serde(flatten)]
    pub tx: transactions::SignedEstablishedAccountTx,
}

#[derive(
    Clone,
    Debug,
    Deserialize,
    Serialize,
    BorshSerialize,
    BorshDeserialize,
    PartialEq,
    Eq,
)]
pub struct FinalizedValidatorAccountTx {
    pub address: Address,
    #[serde(flatten)]
    pub tx: transactions::SignedValidatorAccountTx,
}

/// Chain metadata
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
pub struct Metadata<ID> {
    /// Chain ID in [`Finalized`] or chain ID prefix in
    /// [`GenesisToGenAddresses`] and [`ToFinalize`].
    pub chain_id: ID,
    // Genesis timestamp
    pub genesis_time: Rfc3339String,
    /// The Tendermint consensus timeout_commit configuration
    pub consensus_timeout_commit: DurationNanos,
    /// This generator should be used to initialize the ledger for the
    /// next address that will be generated on chain.
    ///
    /// The value is expected to always be `None` in [`GenesisToGenAddresses`]
    /// and `Some` in [`ToFinalize`] and [`Finalized`].
    pub address_gen: Option<EstablishedAddressGen>,
}

#[cfg(test)]
mod test {
    use std::path::PathBuf;
    use std::str::FromStr;

    use super::*;

    /// Test that the [`finalize`] returns deterministic output with the same
    /// chain ID for the same input.
    #[test]
    fn test_finalize_is_deterministic() {
        // Load the localnet templates
        let templates_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .join("genesis/localnet");
        let templates = templates::load_and_validate(&templates_dir).unwrap();

        let chain_id_prefix: ChainIdPrefix =
            FromStr::from_str("test-prefix").unwrap();

        let genesis_time =
            DateTimeUtc::from_str("2021-12-31T00:00:00Z").unwrap();

        let consensus_timeout_commit =
            crate::facade::tendermint::Timeout::from_str("1s").unwrap();

        let finalized_0 = finalize(
            templates.clone(),
            chain_id_prefix.clone(),
            genesis_time.clone(),
            consensus_timeout_commit.clone(),
        );

        let finalized_1 = finalize(
            templates,
            chain_id_prefix,
            genesis_time,
            consensus_timeout_commit,
        );

        pretty_assertions::assert_eq!(finalized_0, finalized_1);
    }
}
