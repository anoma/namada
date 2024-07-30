//! A module for loading WASM files and downloading pre-built WASMs.
use core::borrow::Borrow;
use std::fs;
use std::path::Path;

use data_encoding::HEXLOWER;
use eyre::{eyre, WrapErr};
use futures::future::join_all;
use namada_sdk::collections::HashMap;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::io::AsyncReadExt;

use crate::cli::safe_exit;
use crate::config::DEFAULT_WASM_CHECKSUMS_FILE;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Not able to download {0}, failed with {1}")]
    Download(String, reqwest::Error),
    #[error("Error writing to {0}")]
    FileWrite(String),
    #[error("Cannot download {0}")]
    WasmNotFound(String),
    #[error("Error while downloading {0}: {1}")]
    ServerError(String, String),
    #[error("Checksum mismatch in downloaded wasm: {0}")]
    ChecksumMismatch(String),
}

/// A hash map where keys are simple file names and values their full file name
/// including SHA256 hash
#[derive(Debug, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Checksums(pub HashMap<String, String>);

/// Github URL prefix of released Namada network configs
pub const ENV_VAR_WASM_SERVER: &str = "NAMADA_NETWORK_WASM_SERVER";
const DEFAULT_WASM_SERVER: &str = "https://artifacts.heliax.click/namada-wasm";

impl Checksums {
    /// Read WASM checksums from the given path
    pub fn read_checksums_file(
        checksums_path: impl AsRef<Path>,
    ) -> Result<Self, eyre::Error> {
        match fs::File::open(&checksums_path) {
            Ok(file) => match serde_json::from_reader(file) {
                Ok(result) => Ok(result),
                Err(_) => {
                    eprintln!(
                        "Can't read checksums from {}",
                        checksums_path.as_ref().to_string_lossy()
                    );
                    Err(eyre!(
                        "Can't read checksums from {}",
                        checksums_path.as_ref().to_string_lossy()
                    ))
                }
            },
            Err(_) => {
                eprintln!(
                    "Can't find checksums at {}",
                    checksums_path.as_ref().to_string_lossy()
                );
                Err(eyre!(
                    "Can't find checksums at {}",
                    checksums_path.as_ref().to_string_lossy()
                ))
            }
        }
    }

    /// Read WASM checksums from "checksums.json" in the given directory
    pub fn read_checksums(
        wasm_directory: impl AsRef<Path>,
    ) -> Result<Self, eyre::Error> {
        let checksums_path =
            wasm_directory.as_ref().join(DEFAULT_WASM_CHECKSUMS_FILE);
        Self::read_checksums_file(checksums_path)
    }

    pub async fn read_checksums_async(
        wasm_directory: impl AsRef<Path>,
    ) -> Self {
        let checksums_path =
            wasm_directory.as_ref().join(DEFAULT_WASM_CHECKSUMS_FILE);
        match tokio::fs::File::open(&checksums_path).await {
            Ok(mut file) => {
                let mut contents = vec![];
                // Ignoring the result, next step will fail if not read
                let _ = file.read_to_end(&mut contents).await;
                match serde_json::from_slice(&contents[..]) {
                    Ok(checksums) => checksums,
                    Err(err) => {
                        eprintln!(
                            "Failed decoding WASM checksums from {}. Failed \
                             with {}",
                            checksums_path.to_string_lossy(),
                            err
                        );
                        safe_exit(1);
                    }
                }
            }
            Err(err) => {
                eprintln!(
                    "Unable to read WASM checksums from {}. Failed with {}",
                    checksums_path.to_string_lossy(),
                    err
                );
                safe_exit(1);
            }
        }
    }
}

fn wasm_url(wasm_name: &str) -> String {
    let prefix_url = std::env::var(ENV_VAR_WASM_SERVER)
        .unwrap_or_else(|_| DEFAULT_WASM_SERVER.to_string());
    format!("{}/{}", prefix_url, wasm_name)
}

fn valid_wasm_checksum(
    wasm_payload: &[u8],
    name: &str,
    full_name: &str,
) -> Result<(), String> {
    let mut hasher = Sha256::new();
    hasher.update(wasm_payload);
    let result = HEXLOWER.encode(&hasher.finalize());
    let derived_name = format!(
        "{}.{}.wasm",
        &name.split('.').collect::<Vec<&str>>()[0],
        result
    );
    if full_name == derived_name {
        Ok(())
    } else {
        Err(derived_name)
    }
}

/// Download all the pre-built wasms, or if they're already downloaded, verify
/// their checksums.
pub async fn pre_fetch_wasm(wasm_directory: impl AsRef<Path>) {
    // load json with wasm hashes
    let checksums = Checksums::read_checksums_async(&wasm_directory).await;

    join_all(checksums.0.into_iter().map(|(name, full_name)| {
        let wasm_directory = wasm_directory.as_ref().to_owned();

        // Async check and download (if needed) each file
        tokio::spawn(async move {
            let wasm_path = wasm_directory.join(&full_name);
            match tokio::fs::read(&wasm_path).await {
                // if the file exist, first check the hash. If not matching
                // download it again.
                Ok(bytes) => {
                    if let Err(derived_name) =
                        valid_wasm_checksum(&bytes, &name, &full_name)
                    {
                        tracing::info!(
                            "WASM checksum mismatch: Got {}, expected {}. \
                             Fetching new version...",
                            derived_name,
                            full_name
                        );
                    } else {
                        return;
                    }

                    match download_wasm(&name, &full_name).await {
                        Ok(bytes) => {
                            if let Err(e) =
                                tokio::fs::write(wasm_path, &bytes).await
                            {
                                eprintln!(
                                    "Error while creating file for {}: {}",
                                    &name, e
                                );
                                safe_exit(1);
                            }
                        }
                        Err(e) => {
                            eprintln!("Error downloading wasm: {}", e);
                            safe_exit(1);
                        }
                    }
                }
                // if the doesn't file exist, download it.
                Err(err) => match err.kind() {
                    std::io::ErrorKind::NotFound => {
                        match download_wasm(&name, &full_name).await {
                            Ok(bytes) => {
                                if let Err(e) =
                                    tokio::fs::write(wasm_path, &bytes).await
                                {
                                    eprintln!(
                                        "Error while creating file for {}: {}",
                                        &name, e
                                    );
                                    safe_exit(1);
                                }
                            }
                            Err(e) => {
                                eprintln!("Error downloading wasm: {}", e);
                                safe_exit(1);
                            }
                        }
                    }
                    _ => {
                        eprintln!(
                            "Can't read {}.",
                            wasm_path.as_os_str().to_string_lossy()
                        );
                        safe_exit(1);
                    }
                },
            }
        })
    }))
    .await;
}

pub fn read_wasm(
    wasm_directory: impl AsRef<Path>,
    file_path: impl AsRef<Path>,
) -> eyre::Result<Vec<u8>> {
    // load json with wasm hashes
    let checksums = Checksums::read_checksums(&wasm_directory)?;

    if let Some(os_name) = file_path.as_ref().file_name() {
        if let Some(name) = os_name.to_str() {
            let wasm_path = match checksums.0.get(name) {
                Some(wasm_filename) => {
                    wasm_directory.as_ref().join(wasm_filename)
                }
                None => {
                    if !file_path.as_ref().is_absolute() {
                        wasm_directory.as_ref().join(file_path.as_ref())
                    } else {
                        file_path.as_ref().to_path_buf()
                    }
                }
            };
            return fs::read(&wasm_path).wrap_err_with(|| {
                format!(
                    "Failed to read WASM from {}",
                    &wasm_path.to_string_lossy()
                )
            });
        }
    }
    Err(eyre!(
        "Could not read {}",
        file_path.as_ref().to_string_lossy()
    ))
}

pub fn read_wasm_or_exit(
    wasm_directory: impl AsRef<Path>,
    file_path: impl AsRef<Path>,
) -> Vec<u8> {
    match read_wasm(wasm_directory, file_path) {
        Ok(wasm) => wasm,
        Err(err) => {
            eprintln!("Error reading wasm: {}", err);
            safe_exit(1);
        }
    }
}

async fn download_wasm(name: &str, full_name: &str) -> Result<Vec<u8>, Error> {
    let url = wasm_url(full_name);

    tracing::info!("Downloading WASM {url}...");

    let response = reqwest::get(&url).await;

    match response {
        Ok(body) => {
            let status = body.status();
            if status.is_success() {
                let bytes = body.bytes().await.unwrap();
                let bytes: &[u8] = bytes.borrow();

                valid_wasm_checksum(bytes, name, full_name)
                    .map_err(Error::ChecksumMismatch)?;

                let bytes: Vec<u8> = bytes.to_owned();

                Ok(bytes)
            } else if status.is_server_error() {
                Err(Error::WasmNotFound(url))
            } else {
                Err(Error::ServerError(url, status.to_string()))
            }
        }
        Err(e) => Err(Error::Download(url, e)),
    }
}
