use core::borrow::Borrow;
use std::collections::HashMap;
use std::fs;
use std::path::Path;

use hex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Not able to download {0}")]
    Download(String),
    #[error("Error writing to {0}")]
    FileWrite(String),
    #[error("Cannot download {0}")]
    WasmNotFound(String),
    #[error("Error while downloading {0}: {1}")]
    ServerError(String, String),
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(transparent)]
struct Checksums(HashMap<String, String>);

const S3_URL: &str = "https://heliax-anoma-wasm-v1.s3.eu-west-1.amazonaws.com";

impl Checksums {
    pub fn read_checksums(path: impl AsRef<Path>) -> Self {
        let file = fs::File::open(path).expect("file should open read only");
        serde_json::from_reader(file).expect("file should be proper JSON")
    }
}

pub fn pre_fetch_wasm(
    wasm_directory: impl AsRef<Path>,
    checksums_path: impl AsRef<Path>,
) {
    // load json with wasm hashes
    let checksums = Checksums::read_checksums(checksums_path);

    for (name, hash) in checksums.0 {
        let wasm_path = wasm_directory.as_ref().join(&hash);

        match fs::read(&wasm_path) {
            // if the file exist, first check the hash. If not matching download
            // it again.
            Ok(bytes) => {
                let mut hasher = Sha256::new();
                hasher.update(bytes);
                let result = hex::encode(hasher.finalize());
                let checksum = format!(
                    "{}.{}.wasm",
                    &name.split(".").collect::<Vec<&str>>()[0],
                    result
                );
                if hash == checksum {
                    continue;
                }
                tracing::info!(
                    "Wasm checksum mismatch for {}. Fetching new version...",
                    &name,
                );
                let url = format!("{}/{}", S3_URL, hash);
                match download_wasm(url) {
                    Ok(bytes) => {
                        if let Err(e) = fs::write(wasm_path, &bytes) {
                            panic!(
                                "Error while creating file for {}: {}",
                                &name, e
                            );
                        }
                    }
                    Err(e) => {
                        panic!("Error: {}", e);
                    }
                }
            }
            // if the doesn't file exist, download it.
            Err(err) => {
                match err.kind() {
                    std::io::ErrorKind::NotFound => {
                        // load it from external storage
                        let url = format!("{}/{}", S3_URL, hash);
                        let response = reqwest::blocking::get(&url);
                        match response {
                            Ok(body) => {
                                let bytes = body.bytes().unwrap();
                                let bytes: &[u8] = bytes.borrow();
                                let bytes: Vec<u8> = bytes.to_owned();

                                if let Err(e) = fs::write(wasm_path, &bytes) {
                                    tracing::warn!(
                                        "Error while creating file for {}: {}",
                                        &name,
                                        e
                                    );
                                } else {
                                    tracing::info!(
                                        "Created {} in {} folder",
                                        &name,
                                        &wasm_directory
                                            .as_ref()
                                            .to_string_lossy()
                                    );
                                }
                            }
                            Err(_) => {
                                tracing::error!(
                                    "Error while downloading file {} from {}",
                                    &name,
                                    url
                                );
                            }
                        }
                    }
                    _ => panic!(
                        "Unrecoverable error while reading {}. Error: {}",
                        wasm_path.to_string_lossy(),
                        err
                    ),
                }
            }
        }
    }
}

pub fn read_wasm(
    wasm_directory: impl AsRef<Path>,
    checksums_path: impl AsRef<Path>,
    name: impl AsRef<str>,
) -> Vec<u8> {
    // load json with wasm hashes
    let checksums = Checksums::read_checksums(checksums_path);

    // construct the absolute path from hash
    let wasm_hash = checksums.0.get(name.as_ref()).unwrap();
    let wasm_path = wasm_directory.as_ref().join(wasm_hash);

    // try to read wasm artifact. If not found, download it
    match fs::read(&wasm_path) {
        Ok(bytes) => bytes,
        Err(_) => {
            panic!(
                "File {} not found. Restart the ledger.",
                wasm_path.to_string_lossy()
            );
        }
    }
}

fn download_wasm(url: String) -> Result<Vec<u8>, Error> {
    let response = reqwest::blocking::get(&url);
    match response {
        Ok(body) => {
            let status = body.status();
            if status.is_success() {
                let bytes = body.bytes().unwrap();
                let bytes: &[u8] = bytes.borrow();
                let bytes: Vec<u8> = bytes.to_owned();

                Ok(bytes)
            } else if status.is_server_error() {
                Err(Error::WasmNotFound(url))
            } else {
                Err(Error::ServerError(url, status.to_string()))
            }
        }
        Err(e) => {
            tracing::error!(
                "Error while downloading file {}. Error: {}",
                url,
                e
            );
            Err(Error::Download(url))
        }
    }
}
