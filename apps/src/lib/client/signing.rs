//! Helpers for making digital signatures using cryptographic keys from the
//! wallet.

use std::rc::Rc;

use anoma::types::address::Address;
use anoma::types::key::ed25519::Keypair;

use super::rpc;
use crate::{cli, wallet};

/// Find the public key for the given address and try to load the keypair for it
/// from the wallet. Panics if the key cannot be found or loaded.
// The lifetime annotations are required, because the return type's lifetime
// depends on the wallet's lifetime, from which it reads the value.
#[allow(clippy::needless_lifetimes)]
pub async fn find_keypair(
    wallet: &mut wallet::Wallet,
    addr: &Address,
    ledger_address: tendermint::net::Address,
) -> Rc<Keypair> {
    let public_key = rpc::get_public_key(addr, ledger_address)
        .await
        .unwrap_or_else(|| {
            eprintln!("No public key found for the address {}", addr.encode());
            std::process::exit(1);
        });
    wallet.find_key_by_pk(&public_key).unwrap_or_else(|err| {
        eprintln!(
            "Unable to load the keypair from the wallet for public key {}. \
             Failed with: {}",
            public_key, err
        );
        cli::safe_exit(1)
    })
}
