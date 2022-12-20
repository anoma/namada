//! Helpers for making digital signatures using cryptographic keys from the
//! wallet.

use namada::ledger::rpc::TxBroadcastData;
use namada::ledger::signing::TxSigningKey;
use namada::ledger::wallet::{Wallet, WalletUtils};
use namada::proto::Tx;
use namada::types::address::Address;
use namada::types::key::*;
use namada::types::storage::Epoch;
use namada::ledger::tx;

use crate::cli::args;
use crate::facade::tendermint_rpc::Client;

/// Find the public key for the given address and try to load the keypair
/// for it from the wallet. Panics if the key cannot be found or loaded.
pub async fn find_keypair<
    C: Client + namada::ledger::queries::Client + Sync,
    U: WalletUtils,
>(
    client: &C,
    wallet: &mut Wallet<U>,
    addr: &Address,
) -> Result<common::SecretKey, tx::Error> {
    namada::ledger::signing::find_keypair::<C, U>(client, wallet, addr).await
}

/// Given CLI arguments and some defaults, determine the rightful transaction
/// signer. Return the given signing key or public key of the given signer if
/// possible. If no explicit signer given, use the `default`. If no `default`
/// is given, panics.
pub async fn tx_signer<
    C: Client + namada::ledger::queries::Client + Sync,
    U: WalletUtils,
>(
    client: &C,
    wallet: &mut Wallet<U>,
    args: &args::Tx,
    default: TxSigningKey,
) -> Result<common::SecretKey,tx::Error> {
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
pub async fn sign_tx<
    C: Client + namada::ledger::queries::Client + Sync,
    U: WalletUtils,
>(
    client: &C,
    wallet: &mut Wallet<U>,
    tx: Tx,
    args: &args::Tx,
    default: TxSigningKey,
) -> Result<TxBroadcastData,tx::Error> {
    namada::ledger::signing::sign_tx::<C, U>(client, wallet, tx, args, default)
        .await
}

/// Create a wrapper tx from a normal tx. Get the hash of the
/// wrapper and its payload which is needed for monitoring its
/// progress on chain.
pub async fn sign_wrapper(
    args: &args::Tx,
    epoch: Epoch,
    tx: Tx,
    keypair: &common::SecretKey,
) -> TxBroadcastData {
    namada::ledger::signing::sign_wrapper(args, epoch, tx, keypair).await
}
