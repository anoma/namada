//! Global configuration

use std::fs::{create_dir_all, File};
use std::io::Write;
use std::path::{Path, PathBuf};

use namada_sdk::chain::ChainId;
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const FILENAME: &str = "global-config.toml";

#[derive(Error, Debug)]
pub enum Error {
    #[error("Error while reading config: {0}")]
    ReadError(config::ConfigError),
    #[error("Error while deserializing config: {0}")]
    DeserializationError(config::ConfigError),
    #[error("Error while writing config: {0}")]
    WriteError(std::io::Error),
    #[error("Error while serializing to toml: {0}")]
    TomlError(toml::ser::Error),
}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct GlobalConfig {
    /// The default chain ID
    pub default_chain_id: Option<ChainId>,
    // NOTE: There will be sub-chains in here in future
}

impl GlobalConfig {
    pub fn new(default_chain_id: ChainId) -> Self {
        Self {
            default_chain_id: Some(default_chain_id),
        }
    }

    /// Try to read the global config from a file. Returns a config without
    /// a `default_chain_id` if none exists.
    pub fn read(base_dir: impl AsRef<Path>) -> Result<Self> {
        let file_path = Self::file_path(base_dir.as_ref());
        let file_name = file_path.to_str().expect("Expected UTF-8 file path");
        let mut config = config::Config::default();
        if file_path.exists() {
            config = config::Config::builder()
                .add_source(config::File::with_name(file_name))
                .build()
                .map_err(Error::ReadError)?;
        }
        config
            .try_deserialize()
            .map_err(|e: config::ConfigError| Error::DeserializationError(e))
    }

    /// Write configuration to a file.
    pub fn write(&self, base_dir: impl AsRef<Path>) -> Result<()> {
        let file_path = Self::file_path(base_dir.as_ref());
        let file_dir = file_path.parent().unwrap();
        create_dir_all(file_dir).map_err(Error::WriteError)?;
        let mut file = File::create(file_path).map_err(Error::WriteError)?;
        let toml = toml::ser::to_string(&self).map_err(|err| {
            if let toml::ser::Error::ValueAfterTable = err {
                tracing::error!("{}", super::VALUE_AFTER_TABLE_ERROR_MSG);
            }
            Error::TomlError(err)
        })?;
        file.write_all(toml.as_bytes()).map_err(Error::WriteError)
    }

    /// Get the file path to the global config
    pub fn file_path(base_dir: impl AsRef<Path>) -> PathBuf {
        base_dir.as_ref().join(FILENAME)
    }
}
