use std::path::Path;

use eyre::Context;
use ledger_namada_rs::NamadaApp;
<<<<<<< HEAD
use namada_sdk::collections::HashSet;
=======
>>>>>>> 52d0ebbd7c (Revert "ci: minors")
use namada_sdk::key::common;
use namada_sdk::tx::Tx;
use namada_sdk::wallet::Wallet;
use namada_sdk::{error, signing};
use serde::de::DeserializeOwned;
use serde::Serialize;
use tokio::sync::RwLock;

use crate::wallet::CliWalletUtils;

/// Validity predicaty assigned to established accounts.
pub const VP_USER: &str = "vp_user";

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

pub(super) async fn with_hardware_wallet<'a, T>(
    tx: Tx,
    pubkey: common::PublicKey,
<<<<<<< HEAD
    parts: HashSet<signing::Signable>,
=======
    parts: signing::Signable,
>>>>>>> 52d0ebbd7c (Revert "ci: minors")
    (wallet, app): (&RwLock<Wallet<CliWalletUtils>>, &NamadaApp<T>),
) -> Result<Tx, error::Error>
where
    T: ledger_transport::Exchange + Send + Sync,
    <T as ledger_transport::Exchange>::Error: std::error::Error,
{
<<<<<<< HEAD
    if parts.contains(&signing::Signable::FeeHeader) {
=======
    if parts == signing::Signable::FeeRawHeader {
>>>>>>> 52d0ebbd7c (Revert "ci: minors")
        Ok(tx)
    } else {
        crate::client::tx::with_hardware_wallet(
            tx,
            pubkey,
            parts,
            (wallet, app),
        )
        .await
    }
}
