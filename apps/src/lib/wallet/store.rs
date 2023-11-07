use std::path::{Path, PathBuf};

use namada::types::key::*;
use namada_sdk::wallet::{gen_sk_rng, LoadStoreError, Store, ValidatorKeys};

use crate::wallet::CliWalletUtils;

/// Wallet file name
const FILE_NAME: &str = "wallet.toml";

/// Get the path to the wallet store.
pub fn wallet_file(store_dir: impl AsRef<Path>) -> PathBuf {
    store_dir.as_ref().join(FILE_NAME)
}

/// Load the store file or create a new one without any keys or addresses.
pub fn load_or_new(store_dir: &Path) -> Result<Store, LoadStoreError> {
    load(store_dir).or_else(|_| {
        let wallet = CliWalletUtils::new(store_dir.to_path_buf());
        wallet.save()?;
        Ok(wallet.into())
    })
}

/// Attempt to load the store file.
pub fn load(store_dir: &Path) -> Result<Store, LoadStoreError> {
    let mut wallet = CliWalletUtils::new(store_dir.to_path_buf());
    wallet.load()?;
    Ok(wallet.into())
}

/// Generate keypair for signing protocol txs and for the DKG
/// A protocol keypair may be optionally provided
///
/// Note that this removes the validator data.
pub fn gen_validator_keys(
    eth_bridge_keypair: Option<common::SecretKey>,
    protocol_keypair: Option<common::SecretKey>,
    protocol_keypair_scheme: SchemeType,
) -> ValidatorKeys {
    let eth_bridge_keypair = eth_bridge_keypair
        .map(|k| {
            if !matches!(&k, common::SecretKey::Secp256k1(_)) {
                panic!("Ethereum bridge keys can only be of kind Secp256k1");
            }
            k
        })
        .unwrap_or_else(|| gen_sk_rng(SchemeType::Secp256k1));
    let protocol_keypair =
        protocol_keypair.unwrap_or_else(|| gen_sk_rng(protocol_keypair_scheme));
    ValidatorKeys {
        protocol_keypair,
        eth_bridge_keypair,
    }
}

#[cfg(test)]
mod test_wallet {
    use namada::types::address::Address;

    use super::*;

    #[test]
    fn test_toml_roundtrip_ed25519() {
        let mut store = Store::default();
        let validator_keys =
            gen_validator_keys(None, None, SchemeType::Ed25519);
        store.add_validator_data(
            Address::decode("atest1v4ehgw36x3prswzxggunzv6pxqmnvdj9xvcyzvpsggeyvs3cg9qnywf589qnwvfsg5erg3fkl09rg5").unwrap(),
            validator_keys
        );
        let data = store.encode();
        let _ = Store::decode(data).expect("Test failed");
    }

    #[test]
    fn test_toml_roundtrip_secp256k1() {
        let mut store = Store::default();
        let validator_keys =
            gen_validator_keys(None, None, SchemeType::Secp256k1);
        store.add_validator_data(
            Address::decode("atest1v4ehgw36x3prswzxggunzv6pxqmnvdj9xvcyzvpsggeyvs3cg9qnywf589qnwvfsg5erg3fkl09rg5").unwrap(),
            validator_keys
        );
        let data = store.encode();
        let _ = Store::decode(data).expect("Test failed");
    }
}
