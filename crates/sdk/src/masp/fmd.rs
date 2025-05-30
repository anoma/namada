//! Commands for FMD key management.
use namada_core::key::FmdKeyHash;
use namada_wallet::DatedViewingKey;

use crate::{ShieldedUtils, ShieldedWallet};

/// Add an FMD key derived from the viewing key
/// to the config file. This file will be used
/// for registering and querying data from Kassandra
/// services.
pub async fn add_service<U: ShieldedUtils>(
    wallet: ShieldedWallet<U>,
    DatedViewingKey { key, .. }: DatedViewingKey,
    url: &str,
) -> kassandra_client::error::Result<()> {
    let uuid = kassandra_client::get_host_uuid(url)?;
    let fmd_key = namada_core::masp::FmdSecretKey::from(&key).fmd_secret_key();
    let enc_key = kassandra_client::encryption_key(&fmd_key, &uuid);
    let key_hash = FmdKeyHash::from(fmd_key).to_string();
    let mut config = U::fmd_config_load().await?;
    config.add_service(key_hash, url, enc_key);
    wallet.utils.fmd_config_save(&mut config).await
}

/// Register FND keys with Kassandra services as specified in the
/// config file.
pub async fn register_keys<U: ShieldedUtils>(
    DatedViewingKey { key, birthday }: DatedViewingKey,
) -> kassandra_client::error::Result<()> {
    let config = U::fmd_config_load().await?;
    let fmd_key = namada_core::masp::FmdSecretKey::from(&key).fmd_secret_key();
    let key_hash = FmdKeyHash::from(&fmd_key).to_string();
    kassandra_client::register_fmd_key(
        &config,
        key_hash,
        &fmd_key,
        Some(birthday.0),
    )
}
