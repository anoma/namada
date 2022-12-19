use std::path::Path;

use borsh::{BorshDeserialize, BorshSerialize};
use namada::types::chain::{ChainId, ChainIdPrefix};
use namada::types::time::{DateTimeUtc, DurationNanos, Rfc3339String};
use serde::{Deserialize, Serialize};

use super::templates;
use super::toml_utils::{read_toml, write_toml};

pub const METADATA_FILE_NAME: &str = "chain.toml";

impl Finalized {
    /// Write all genesis and the chain metadata TOML files to the given
    /// directory.
    pub fn write_toml_files(&self, output_dir: &Path) -> eyre::Result<()> {
        self.templates.write_toml_files(output_dir)?;
        let metadata_file = output_dir.join(METADATA_FILE_NAME);
        write_toml(&self.metadata, &metadata_file, "Chain metadata")?;
        Ok(())
    }

    /// Try to read all genesis and the chain metadata TOML files from the given
    /// directory.
    pub fn read_toml_files(input_dir: &Path) -> eyre::Result<Self> {
        let templates = templates::All::read_toml_files(input_dir)?;
        let metadata_file = input_dir.join(METADATA_FILE_NAME);
        let metadata = read_toml(&metadata_file, "Chain metadata")?;
        Ok(Self {
            templates,
            metadata,
        })
    }
}

/// Create the [`Finalized`] chain configuration.
pub fn finalize(
    templates: templates::All,
    chain_id_prefix: ChainIdPrefix,
    genesis_time: DateTimeUtc,
    consensus_timeout_commit: crate::facade::tendermint::Timeout,
) -> Finalized {
    let genesis_time: Rfc3339String = genesis_time.into();
    let consensus_timeout_commit: DurationNanos =
        consensus_timeout_commit.into();
    let genesis = ToFinalize {
        templates,
        metadata: Metadata {
            chain_id: chain_id_prefix.clone(),
            genesis_time,
            consensus_timeout_commit,
        },
    };
    let genesis_bytes = genesis.try_to_vec().unwrap();
    let chain_id = ChainId::from_genesis(chain_id_prefix, genesis_bytes);
    let metadata = Metadata {
        chain_id,
        genesis_time: genesis.metadata.genesis_time,
        consensus_timeout_commit: genesis.metadata.consensus_timeout_commit,
    };
    Finalized {
        templates: genesis.templates,
        metadata,
    }
}

/// Finalized chain genesis configuration.
pub type Finalized = Chain<ChainId>;

/// Chain genesis config to be finalized. This struct is used to derive the
/// chain ID to construct a [`Finalized`] chain genesis config.
pub type ToFinalize = Chain<ChainIdPrefix>;

#[derive(
    Clone, Debug, Deserialize, Serialize, BorshDeserialize, BorshSerialize,
)]
pub struct Chain<ID> {
    /// Chain ID
    pub templates: templates::All,
    /// Chain metadata
    pub metadata: Metadata<ID>,
}

/// Chain metadata
#[derive(
    Clone, Debug, Deserialize, Serialize, BorshDeserialize, BorshSerialize,
)]
pub struct Metadata<ID> {
    /// Chain ID
    pub chain_id: ID,
    // Genesis timestamp
    pub genesis_time: Rfc3339String,
    /// The Tendermint consensus timeout_commit configuration
    pub consensus_timeout_commit: DurationNanos,
}
