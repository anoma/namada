//! Helpers for making digital signatures using cryptographic keys from the
//! wallet.

use namada::ledger::rpc::TxBroadcastData;
use namada::ledger::signing::TxSigningKey;
use namada::ledger::tx;
use namada::ledger::wallet::{Wallet, WalletUtils};
use namada::proof_of_stake::Epoch;
use namada::proto::Tx;
use namada::types::address::Address;
use namada::types::key::*;
use std::borrow::Cow;
use std::collections::BTreeMap;

use crate::cli::args;

/// Find the public key for the given address and try to load the keypair
/// for it from the wallet. Panics if the key cannot be found or loaded.
pub async fn find_keypair<
    C: namada::ledger::queries::Client + Sync,
    U: WalletUtils,
>(
    client: &C,
    wallet: &mut Wallet<U>,
    addr: &Address,
) -> Result<common::SecretKey, tx::Error> {
    namada::ledger::signing::find_keypair::<C, U>(client, wallet, addr, None)
        .await
}

/// Given CLI arguments and some defaults, determine the rightful transaction
/// signer. Return the given signing key or public key of the given signer if
/// possible. If no explicit signer given, use the `default`. If no `default`
/// is given, panics.
pub async fn tx_signer<
    C: namada::ledger::queries::Client + Sync,
    U: WalletUtils,
>(
    client: &C,
    wallet: &mut Wallet<U>,
    args: &args::Tx,
    default: TxSigningKey,
) -> Result<common::SecretKey, tx::Error> {
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
///
/// If the tx fee is to be unshielded, it also returns the unshielding epoch.
pub async fn sign_tx<
    C: namada::ledger::queries::Client + Sync,
    U: WalletUtils,
>(
    client: &C,
    wallet: &mut Wallet<U>,
    tx: Tx,
    args: &args::Tx,
    default: TxSigningKey,
    mut updated_balance: Option<Amount>,
    #[cfg(not(feature = "mainnet"))] requires_pow: bool,
) -> Result<(TxBroadcastData, Option<Epoch>), tx::Error> {
    namada::ledger::signing::sign_tx::<C, U>(
        client,
        wallet,
        tx,
        args,
        default,
        #[cfg(not(feature = "mainnet"))]
        requires_pow,
    )
    .await
}

/// Create a wrapper tx from a normal tx. Get the hash of the
/// wrapper and its payload which is needed for monitoring its
/// progress on chain. Accepts an optional balance reflecting any modification applied to it by the inner tx for a correct fee validation.
pub async fn sign_wrapper<
    'key,
    C: namada::ledger::queries::Client + Sync,
    U: WalletUtils,
>(
    client: &C,
    wallet: &mut Wallet<U>,
    args: &args::Tx,
    epoch: Epoch,
    tx: Tx,
    mut keypair: Cow<'key, common::SecretKey>,
    mut updated_balance: Option<Amount>,
    #[cfg(not(feature = "mainnet"))] requires_pow: bool,
) -> (TxBroadcastData, Option<Epoch>) {
    namada::ledger::signing::sign_wrapper(
        client,
        wallet,
        args,
        epoch,
        tx,
        keypair,
        updated_balance,
        #[cfg(not(feature = "mainnet"))]
        requires_pow,
    )
    .await
}
