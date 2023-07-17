//! Helpers for making digital signatures using cryptographic keys from the
//! wallet.

use namada::core::types::account::AccountPublicKeysMap;
use namada::ledger::rpc::TxBroadcastData;
use namada::ledger::signing::TxSigningKey;
use namada::ledger::tx;
use namada::ledger::wallet::{Wallet, WalletUtils};
use namada::proof_of_stake::Epoch;
use namada::proto::Tx;
use namada::types::address::Address;
use namada::types::key::*;

use crate::cli::args;

/// Find the public key for the given address and try to load the keypair
/// for it from the wallet. Panics if the key cannot be found or loaded.
pub async fn find_pk<C, U>(
    client: &C,
    wallet: &mut Wallet<U>,
    addr: &Address,
) -> Result<common::PublicKey, tx::Error>
where
    C: namada::ledger::queries::Client + Sync,
    C::Error: std::fmt::Display,
    U: WalletUtils,
{
    namada::ledger::signing::find_pk(client, wallet, addr, None).await
}

/// Given CLI arguments and some defaults, determine the rightful transaction
/// signer. Return the given signing key or public key of the given signer if
/// possible. If no explicit signer given, use the `default`. If no `default`
/// is given, panics.
pub async fn tx_signer<C, U>(
    client: &C,
    wallet: &mut Wallet<U>,
    args: &args::Tx,
    default: TxSigningKey,
) -> Result<(Option<Address>, Vec<common::PublicKey>), tx::Error>
where
    C: namada::ledger::queries::Client + Sync,
    C::Error: std::fmt::Display,
    U: WalletUtils,
{
    namada::ledger::signing::tx_signer::<C, U>(client, wallet, args, default)
        .await
}

/// Sign a transaction with a given signing key or public key of a given signer.
/// If no explicit signer given, use the `default`. If no `default` is given,
/// panics.
///
/// If this is not a dry run, the tx is put in a wrapper and returned along with
/// hashes needed for monitoring the tx on chain.
///
/// If it is a dry run, it is not put in a wrapper, but returned as is.
pub async fn sign_tx<C, U>(
    wallet: &mut Wallet<U>,
    tx: &mut Tx,
    args: &args::Tx,
    public_keys_index_map: &AccountPublicKeysMap,
    public_keys: &[common::PublicKey],
    threshold: u8,
    _default: &common::PublicKey,
) -> Result<(), tx::Error>
where
    C: namada::ledger::queries::Client + Sync,
    C::Error: std::fmt::Display,
    U: WalletUtils,
{
    namada::ledger::signing::sign_tx(
        wallet,
        tx,
        args,
        public_keys_index_map,
        public_keys,
        threshold,
    )
    .await
}

/// Create a wrapper tx from a normal tx. Get the hash of the
/// wrapper and its payload which is needed for monitoring its
/// progress on chain.
pub async fn sign_wrapper<C, U>(
    client: &C,
    wallet: &mut Wallet<U>,
    args: &args::Tx,
    epoch: Epoch,
    tx: Tx,
    keypair: &common::SecretKey,
    #[cfg(not(feature = "mainnet"))] requires_pow: bool,
) -> TxBroadcastData
where
    C: namada::ledger::queries::Client + Sync,
    C::Error: std::fmt::Display,
    U: WalletUtils,
{
    namada::ledger::signing::sign_wrapper(
        client,
        wallet,
        args,
        epoch,
        tx,
        keypair,
        #[cfg(not(feature = "mainnet"))]
        requires_pow,
    )
    .await
}
