//! Helpers for making digital signatures using cryptographic keys from the
//! wallet.

use std::collections::{BTreeMap, HashMap};
use std::env;
use std::fs::File;
use std::io::{Error, ErrorKind, Write};

use borsh::{BorshDeserialize, BorshSerialize};
use data_encoding::HEXLOWER;
use itertools::Itertools;
use masp_primitives::asset_type::AssetType;
use masp_primitives::transaction::components::sapling::fees::{
    InputView, OutputView,
};
use namada::ledger::parameters::storage as parameter_storage;
use namada::proof_of_stake::Epoch;
use namada::proto::{Section, Signature, Tx};
use namada::types::address::{masp, Address, ImplicitAddress};
use namada::types::key::*;
use namada::types::masp::{ExtendedViewingKey, PaymentAddress};
use namada::types::token;
use namada::types::token::{Amount, Transfer};
use namada::types::transaction::decrypted::DecryptedTx;
use namada::types::transaction::governance::{
    InitProposalData, VoteProposalData,
};
use namada::types::transaction::{
    hash_tx, pos, Fee, InitAccount, InitValidator, TxType, UpdateVp, WrapperTx,
    MIN_FEE,
};
use serde::{Deserialize, Serialize};

use super::rpc;
use crate::cli::context::{WalletAddress, WalletKeypair};
use crate::cli::{self, args, Context};
use crate::facade::tendermint_config::net::Address as TendermintAddress;
use crate::facade::tendermint_rpc::HttpClient;
use namada::ledger::rpc::TxBroadcastData;
use namada::ledger::signing::TxSigningKey;
use namada::ledger::tx;
use namada::ledger::wallet::{Wallet, WalletUtils};
use namada::types::key::*;

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
pub async fn sign_tx<
    C: namada::ledger::queries::Client + Sync,
    U: WalletUtils,
>(
    client: &C,
    wallet: &mut Wallet<U>,
    tx: Tx,
    args: &args::Tx,
    default: TxSigningKey,
    #[cfg(not(feature = "mainnet"))] requires_pow: bool,
) -> Result<TxBroadcastData, tx::Error> {
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
/// progress on chain.
pub async fn sign_wrapper<
        C: namada::ledger::queries::Client + Sync,
    U: WalletUtils,
    >(
    client: &C,
    wallet: &mut Wallet<U>,
    args: &args::Tx,
    epoch: Epoch,
    tx: Tx,
    keypair: &common::SecretKey,
    #[cfg(not(feature = "mainnet"))] requires_pow: bool,
) -> TxBroadcastData {
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
