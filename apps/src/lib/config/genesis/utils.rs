use std::collections::HashSet;
use std::future::Future;
use std::path::Path;

use eyre::Context;
use ledger_namada_rs::NamadaApp;
use ledger_transport_hid::hidapi::HidApi;
use ledger_transport_hid::TransportNativeHID;
use namada::proto::Tx;
use namada::types::key::common;
use namada_sdk::wallet::Wallet;
use namada_sdk::{error, signing};
use serde::de::DeserializeOwned;
use serde::Serialize;
use tokio::sync::RwLock;

use crate::wallet::CliWalletUtils;

pub fn read_toml<T: DeserializeOwned>(
    path: &Path,
    which_file: &str,
) -> eyre::Result<T> {
    let file_contents = std::fs::read_to_string(path).wrap_err_with(|| {
        format!(
            "Couldn't read {which_file} config file from {}",
            path.to_string_lossy()
        )
    })?;
    toml::from_str(&file_contents).wrap_err_with(|| {
        format!(
            "Couldn't parse {which_file} TOML from {}",
            path.to_string_lossy()
        )
    })
}

pub fn write_toml<T: Serialize>(
    data: &T,
    path: &Path,
    which_file: &str,
) -> eyre::Result<()> {
    let file_contents = toml::to_vec(data)
        .wrap_err_with(|| format!("Couldn't format {which_file} to TOML."))?;
    std::fs::write(path, file_contents).wrap_err_with(|| {
        format!(
            "Couldn't write {which_file} TOML to {}",
            path.to_string_lossy()
        )
    })
}

pub(super) fn with_hardware_wallet<F, T>(
    wallet: &RwLock<&mut Wallet<CliWalletUtils>>,
) -> F
where
    F: Fn(Tx, common::PublicKey, HashSet<signing::Signable>) -> T,
    T: Future<Output = Result<Tx, error::Error>> + Sized,
{
    // Setup a reusable context for signing transactions using the Ledger
    let hidapi =
        HidApi::new().map_err(|err| panic!("Failed to create Hidapi: {}", err));
    let app = NamadaApp::new(
        TransportNativeHID::new(&hidapi)
            .map_err(|err| panic!("Unable to connect to Ledger: {}", err))?,
    );
    |tx: Tx, pubkey: common::PublicKey, parts: HashSet<signing::Signable>| async move {
        if parts.contains(&signing::Signable::FeeHeader) {
            return Ok(tx);
        }
        let app = app;
        let with_hw = crate::client::tx::with_hardware_wallet::<CliWalletUtils>(
            wallet, &app,
        );
        with_hw(tx, pubkey, parts).await
    }
}
