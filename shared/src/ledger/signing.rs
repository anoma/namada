//! Functions to sign transactions
use std::borrow::Cow;
use std::collections::{BTreeMap, HashMap};
#[cfg(feature = "std")]
use std::env;
#[cfg(feature = "std")]
use std::fs::File;
use std::io::ErrorKind;
#[cfg(feature = "std")]
use std::io::Write;
use std::path::PathBuf;

use borsh::{BorshDeserialize, BorshSerialize};
use data_encoding::HEXLOWER;
use itertools::Itertools;
use masp_primitives::asset_type::AssetType;
use masp_primitives::transaction::components::sapling::fees::{
    InputView, OutputView,
};
use namada_core::types::address::{
    masp, masp_tx_key, Address, ImplicitAddress,
};
use namada_core::types::token::{self, Amount, DenominatedAmount, MaspDenom};
use namada_core::types::transaction::pos;
use namada_core::types::uint::Uint;
use prost::Message;
use serde::{Deserialize, Serialize};
use sha2::Digest;
use zeroize::Zeroizing;

use crate::ibc::applications::transfer::msgs::transfer::{
    MsgTransfer, TYPE_URL as MSG_TRANSFER_TYPE_URL,
};
use crate::ibc_proto::google::protobuf::Any;
use crate::ledger::masp::make_asset_type;
use crate::ledger::parameters::storage as parameter_storage;
use crate::ledger::rpc::{
    format_denominated_amount, query_wasm_code_hash, TxBroadcastData,
};
use crate::ledger::tx::{
    Error, TX_BOND_WASM, TX_CHANGE_COMMISSION_WASM, TX_IBC_WASM,
    TX_INIT_ACCOUNT_WASM, TX_INIT_PROPOSAL, TX_INIT_VALIDATOR_WASM,
    TX_REVEAL_PK, TX_TRANSFER_WASM, TX_UNBOND_WASM, TX_UPDATE_VP_WASM,
    TX_VOTE_PROPOSAL, TX_WITHDRAW_WASM, VP_USER_WASM,
};
use crate::ledger::wallet::alias::Alias;
pub use crate::ledger::wallet::store::AddressVpType;
use crate::ledger::wallet::{Wallet, WalletUtils};
use crate::ledger::{args, rpc};
use crate::proto::{MaspBuilder, Section, Signature, Tx};
use crate::types::key::*;
use crate::types::masp::{ExtendedViewingKey, PaymentAddress};
use crate::types::storage::Epoch;
use crate::types::token::Transfer;
use crate::types::transaction::governance::{
    InitProposalData, VoteProposalData,
};
use crate::types::transaction::{
    Fee, InitAccount, InitValidator, TxType, UpdateVp, WrapperTx,
};

use super::masp::{ShieldedContext, ShieldedUtils};
use super::rpc::validate_amount;

#[cfg(feature = "std")]
/// Env. var specifying where to store signing test vectors
const ENV_VAR_LEDGER_LOG_PATH: &str = "NAMADA_LEDGER_LOG_PATH";
#[cfg(feature = "std")]
/// Env. var specifying where to store transaction debug outputs
const ENV_VAR_TX_LOG_PATH: &str = "NAMADA_TX_LOG_PATH";

/// Find the public key for the given address and try to load the keypair
/// for it from the wallet. If the keypair is encrypted but a password is not
/// supplied, then it is interactively prompted. Errors if the key cannot be
/// found or loaded.
pub async fn find_pk<
    C: crate::ledger::queries::Client + Sync,
    U: WalletUtils,
>(
    client: &C,
    wallet: &mut Wallet<U>,
    addr: &Address,
    password: Option<Zeroizing<String>>,
) -> Result<common::PublicKey, Error> {
    match addr {
        Address::Established(_) => {
            println!(
                "Looking-up public key of {} from the ledger...",
                addr.encode()
            );
            rpc::get_public_key(client, addr).await.ok_or(Error::Other(
                format!(
                    "No public key found for the address {}",
                    addr.encode()
                ),
            ))
        }
        Address::Implicit(ImplicitAddress(pkh)) => Ok(wallet
            .find_key_by_pkh(pkh, password)
            .map_err(|err| {
                Error::Other(format!(
                    "Unable to load the keypair from the wallet for the \
                     implicit address {}. Failed with: {}",
                    addr.encode(),
                    err
                ))
            })?
            .ref_to()),
        Address::Internal(_) => other_err(format!(
            "Internal address {} doesn't have any signing keys.",
            addr
        )),
    }
}

/// Load the secret key corresponding to the given public key from the wallet.
/// If the keypair is encrypted but a password is not supplied, then it is
/// interactively prompted. Errors if the key cannot be found or loaded.
pub fn find_key_by_pk<U: WalletUtils>(
    wallet: &mut Wallet<U>,
    args: &args::Tx,
    keypair: &common::PublicKey,
) -> Result<common::SecretKey, Error> {
    if *keypair == masp_tx_key().ref_to() {
        // We already know the secret key corresponding to the MASP sentinal key
        Ok(masp_tx_key())
    } else if args
        .signing_key
        .as_ref()
        .map(|x| x.ref_to() == *keypair)
        .unwrap_or(false)
    {
        // We can lookup the secret key from the CLI arguments in this case
        Ok(args.signing_key.clone().unwrap())
    } else {
        // Otherwise we need to search the wallet for the secret key
        wallet
            .find_key_by_pk(keypair, args.password.clone())
            .map_err(|err| {
                Error::Other(format!(
                    "Unable to load the keypair from the wallet for public \
                     key {}. Failed with: {}",
                    keypair, err
                ))
            })
    }
}

/// Carries types that can be directly/indirectly used to sign a transaction.
#[allow(clippy::large_enum_variant)]
#[derive(Clone)]
pub enum TxSigningKey {
    /// Do not sign any transaction
    None,
    /// Obtain the keypair corresponding to given address from wallet and sign
    WalletAddress(Address),
}

/// Given CLI arguments and some defaults, determine the rightful transaction
/// signer. Return the given signing key or public key of the given signer if
/// possible. If no explicit signer given, use the `default`. If no `default`
/// is given, an `Error` is returned.
pub async fn tx_signer<
    C: crate::ledger::queries::Client + Sync,
    U: WalletUtils,
>(
    client: &C,
    wallet: &mut Wallet<U>,
    args: &args::Tx,
    default: TxSigningKey,
) -> Result<(Option<Address>, common::PublicKey), Error> {
    let signer = if args.dry_run {
        // We cannot override the signer if we're doing a dry run
        default
    } else if let Some(signing_key) = &args.signing_key {
        // Otherwise use the signing key override provided by user
        return Ok((None, signing_key.ref_to()));
    } else if let Some(verification_key) = &args.verification_key {
        return Ok((None, verification_key.clone()));
    } else if let Some(signer) = &args.signer {
        // Otherwise use the signer address provided by user
        TxSigningKey::WalletAddress(signer.clone())
    } else {
        // Otherwise use the signer determined by the caller
        default
    };
    // Now actually fetch the signing key and apply it
    match signer {
        TxSigningKey::WalletAddress(signer) if signer == masp() => {
            Ok((None, masp_tx_key().ref_to()))
        }
        TxSigningKey::WalletAddress(signer) => Ok((
            Some(signer.clone()),
            find_pk::<C, U>(client, wallet, &signer, args.password.clone())
                .await?,
        )),
        TxSigningKey::None => other_err(
            "All transactions must be signed; please either specify the key \
             or the address from which to look up the signing key."
                .to_string(),
        ),
    }
}

/// Sign a transaction with a given signing key or public key of a given signer.
/// If no explicit signer given, use the `default`. If no `default` is given,
/// Error.
///
/// If this is not a dry run, the tx is put in a wrapper and returned along with
/// hashes needed for monitoring the tx on chain.
///
/// If it is a dry run, it is not put in a wrapper, but returned as is.
///
/// If the tx fee is to be unshielded, it also returns the unshielding epoch.
pub async fn sign_tx<U: WalletUtils>(
    wallet: &mut Wallet<U>,
    tx: &mut Tx,
    args: &args::Tx,
    keypair: &common::PublicKey,
) -> Result<(), Error> {
    let keypair = find_key_by_pk(wallet, args, keypair)?;
    // Sign over the transacttion data
    tx.add_section(Section::Signature(Signature::new(
        vec![*tx.data_sechash(), *tx.code_sechash()],
        &keypair,
    )));
    // Remove all the sensitive sections
    tx.protocol_filter();
    // Then sign over the bound wrapper
    tx.add_section(Section::Signature(Signature::new(
        tx.sechashes(),
        &keypair,
    )));
    Ok(())
}

#[cfg(not(feature = "mainnet"))]
/// Solve the PoW challenge if balance is insufficient to pay transaction fees
/// or if solution is explicitly requested.
pub async fn solve_pow_challenge<C: crate::ledger::queries::Client + Sync>(
    client: &C,
    args: &args::Tx,
    requires_pow: bool,
    total_fee: Amount,
    balance: Amount,
    source: Address,
) -> Option<crate::core::ledger::testnet_pow::Solution> {
    let is_bal_sufficient = total_fee <= balance;
    if !is_bal_sufficient {
        let token_addr = args.fee_token.clone();
        let err_msg = format!(
            "The wrapper transaction source doesn't have enough balance to \
             pay fee {}, got {}.",
            format_denominated_amount(client, &token_addr, total_fee).await,
            format_denominated_amount(client, &token_addr, balance).await,
        );
        if !args.force && cfg!(feature = "mainnet") {
            panic!("{}", err_msg);
        }
    }
    // A PoW solution can be used to allow zero-fee testnet transactions
    // If the address derived from the keypair doesn't have enough balance
    // to pay for the fee, allow to find a PoW solution instead.
    if requires_pow || !is_bal_sufficient {
        println!("The transaction requires the completion of a PoW challenge.");
        // Obtain a PoW challenge for faucet withdrawal
        let challenge = rpc::get_testnet_pow_challenge(client, source).await;

        // Solve the solution, this blocks until a solution is found
        let solution = challenge.solve();
        Some(solution)
    } else {
        None
    }
}

#[cfg(not(feature = "mainnet"))]
/// Update the PoW challenge inside the given transaction
pub async fn update_pow_challenge<C: crate::ledger::queries::Client + Sync>(
    client: &C,
    args: &args::Tx,
    tx: &mut Tx,
    requires_pow: bool,
    source: Address,
) {
    use std::collections::BTreeMap;

    let gas_cost_key = parameter_storage::get_gas_cost_key();
    let minimum_fee = match rpc::query_storage_value::<
        C,
        BTreeMap<Address, Amount>,
    >(client, &gas_cost_key)
    .await
    .map(|map| map.get(&args.fee_token).map(ToOwned::to_owned))
    .flatten()
    {
        Some(amount) => amount,
        None => {
            if !args.force && cfg!(feature = "mainnet") {
                panic!(
                    "Could not retrieve the gas cost for token {}",
                    args.fee_token
                );
            } else {
                token::Amount::default()
            }
        }
    };
    let fee_amount = match args.fee_amount {
        Some(amount) => {
            let validated_fee_amount =
                validate_amount(client, amount, &args.fee_token, args.force)
                    .await
                    .expect("Expected to be ablo to validate fee");

            let amount = Amount::from_uint(
                validated_fee_amount.amount,
                validated_fee_amount.denom,
            )
            .unwrap();

            amount.max(minimum_fee)
        }
        None => minimum_fee,
    };
    let total_fee = fee_amount * u64::from(args.gas_limit);

    let balance_key = token::balance_key(&args.fee_token, &source);
    let balance =
        rpc::query_storage_value::<C, token::Amount>(client, &balance_key)
            .await
            .unwrap_or_default();

    if let TxType::Wrapper(wrapper) = &mut tx.header.tx_type {
        let pow_solution = solve_pow_challenge(
            client,
            args,
            requires_pow,
            total_fee,
            balance,
            source,
        )
        .await;
        wrapper.fee = Fee {
            amount_per_gas_unit: fee_amount,
            token: args.fee_token.clone(),
        };
        wrapper.pow_solution = pow_solution;
    }
}

/// Create a wrapper tx from a normal tx. Get the hash of the
/// wrapper and its payload which is needed for monitoring its
/// progress on chain.
pub async fn wrap_tx<
    C: crate::ledger::queries::Client + Sync,
    U: WalletUtils,
    V: ShieldedUtils,
>(
    client: &C,
    wallet: &mut Wallet<U>,
    shielded: &mut ShieldedContext<V>,
    mut tx: Tx,
    args: &args::Tx,
    updated_balance: Option<Amount>,
    epoch: Epoch,
    keypair: &common::PublicKey,
    #[cfg(not(feature = "mainnet"))] requires_pow: bool,
) -> (Tx, Option<Epoch>) {
    // Validate fee amount and token
    let gas_cost_key = parameter_storage::get_gas_cost_key();
    let minimum_fee = match rpc::query_storage_value::<
        C,
        BTreeMap<Address, Amount>,
    >(client, &gas_cost_key)
    .await
    .map(|map| map.get(&args.fee_token).map(ToOwned::to_owned))
    .flatten()
    {
        Some(amount) => amount,
        None => {
            if !args.force && cfg!(feature = "mainnet") {
                panic!(
                    "Could not retrieve the gas cost for token {}",
                    args.fee_token
                );
            } else {
                token::Amount::default()
            }
        }
    };
    let fee_amount = match args.fee_amount {
        Some(amount) => {
            let validated_fee_amount =
                validate_amount(client, amount, &args.fee_token, args.force)
                    .await
                    .expect("Expected to be ablo to validate fee");

            let amount = Amount::from_uint(
                validated_fee_amount.amount,
                validated_fee_amount.denom,
            )
            .unwrap();

            amount.max(minimum_fee)
        }
        None => minimum_fee,
    };

    let source = Address::from(keypair);
    let mut updated_balance = match updated_balance {
        Some(balance) => balance,
        None => {
            let balance_key = token::balance_key(&args.fee_token, &source);

            rpc::query_storage_value::<C, token::Amount>(client, &balance_key)
                .await
                .unwrap_or_default()
        }
    };

    let total_fee = fee_amount * u64::from(args.gas_limit);

    let (unshield, unshielding_epoch) = match total_fee
        .checked_sub(updated_balance)
    {
        Some(diff) if !diff.is_zero() => {
            if let Some(spending_key) = args.fee_unshield.clone() {
                // Unshield funds for fee payment
                let tx_args = args::Tx {
                    fee_amount: None,
                    fee_unshield: None,
                    ..args.to_owned()
                };
                let transfer_args = args::TxTransfer {
                    tx: tx_args,
                    source: spending_key,
                    target: namada_core::types::masp::TransferTarget::Address(
                        source.clone(),
                    ),
                    token: args.fee_token.clone(),
                    amount: args::InputAmount::Validated(DenominatedAmount {
                        amount: diff,
                        denom: 0.into(),
                    }),
                    // These last two fields are not used in the function, mock them
                    native_token: args.fee_token.clone(),
                    tx_code_path: PathBuf::new(),
                };

                match shielded
                    .gen_shielded_transfer(client, transfer_args)
                    .await
                {
                    Ok(Some((_, transaction, _data, unshielding_epoch))) => {
                        let spends = transaction
                            .sapling_bundle()
                            .unwrap()
                            .shielded_spends
                            .len();
                        let converts = transaction
                            .sapling_bundle()
                            .unwrap()
                            .shielded_converts
                            .len();
                        let outs = transaction
                            .sapling_bundle()
                            .unwrap()
                            .shielded_outputs
                            .len();

                        let mut descriptions =
                            spends.checked_add(converts).unwrap_or_else(|| {
                                if !args.force && cfg!(feature = "mainnet") {
                                    panic!(
                                        "Overflow in fee unshielding \
                                         descriptions"
                                    );
                                } else {
                                    usize::MAX
                                }
                            });

                        descriptions = descriptions
                            .checked_add(outs)
                            .unwrap_or_else(|| {
                                if !args.force && cfg!(feature = "mainnet") {
                                    panic!(
                                        "Overflow in fee unshielding \
                                         descriptions"
                                    );
                                } else {
                                    usize::MAX
                                }
                            });

                        let descriptions_limit_key=  parameter_storage::get_fee_unshielding_descriptions_limit_key();
                        let descriptions_limit =
                            rpc::query_storage_value::<C, u64>(
                                client,
                                &descriptions_limit_key,
                            )
                            .await
                            .unwrap();

                        if u64::try_from(descriptions).unwrap_or_else(|_| {
                            if !args.force && cfg!(feature = "mainnet") {
                                panic!(
                                    "Overflow in fee unshielding descriptions"
                                );
                            } else {
                                u64::MAX
                            }
                        }) > descriptions_limit
                            && !args.force
                            && cfg!(feature = "mainnet")
                        {
                            panic!(
                                "Fee unshielding descriptions exceed the limit"
                            );
                        }

                        updated_balance += diff;
                        (Some(transaction), Some(unshielding_epoch))
                    }
                    Ok(None) => {
                        eprintln!("Missing unshielding transaction");
                        if !args.force && cfg!(feature = "mainnet") {
                            panic!();
                        }

                        (None, None)
                    }
                    Err(e) => {
                        eprintln!("Error in fee unshielding generation: {}", e);
                        if !args.force && cfg!(feature = "mainnet") {
                            panic!();
                        }

                        (None, None)
                    }
                }
            } else {
                let token_addr = args.fee_token.clone();
                let err_msg = format!(
            "The wrapper transaction source doesn't have enough balance to \
             pay fee {}, balance: {}.",
            format_denominated_amount(client, &token_addr, fee_amount).await,
            format_denominated_amount(client, &token_addr, updated_balance).await,
        );
                eprintln!("{}", err_msg);
                if !args.force && cfg!(feature = "mainnet") {
                    panic!("{}", err_msg);
                }

                (None, None)
            }
        }
        _ => (None, None),
    };

    let unshield_section_hash = unshield.map(|masp_tx| {
        let section = Section::MaspTx(masp_tx);
        let mut hasher = sha2::Sha256::new();
        section.hash(&mut hasher);
        tx.add_section(section);
        namada_core::types::hash::Hash(hasher.finalize().into())
    });

    #[cfg(not(feature = "mainnet"))]
    let pow_solution = solve_pow_challenge(
        client,
        args,
        requires_pow,
        total_fee,
        updated_balance,
        source,
    )
    .await;
    // This object governs how the payload will be processed
    tx.update_header(TxType::Wrapper(Box::new(WrapperTx::new(
        Fee {
            amount_per_gas_unit: fee_amount,
            token: args.fee_token.clone(),
        },
        keypair.clone(),
        epoch,
        //TODO: partially validate the gas limit in client
        args.gas_limit.clone(),
        #[cfg(not(feature = "mainnet"))]
        pow_solution,
        unshield_section_hash,
    ))));
    tx.header.chain_id = args.chain_id.clone().unwrap();
    tx.header.expiration = args.expiration;

    #[cfg(feature = "std")]
    // Attempt to decode the construction
    if let Ok(path) = env::var(ENV_VAR_LEDGER_LOG_PATH) {
        let mut tx = tx.clone();
        // Contract the large data blobs in the transaction
        tx.wallet_filter();
        // Convert the transaction to Ledger format
        let decoding = to_ledger_vector(client, wallet, &tx)
            .await
            .expect("unable to decode transaction");
        let output = serde_json::to_string(&decoding)
            .expect("failed to serialize decoding");
        // Record the transaction at the identified path
        let mut f = File::options()
            .append(true)
            .create(true)
            .open(path)
            .expect("failed to open test vector file");
        writeln!(f, "{},", output)
            .expect("unable to write test vector to file");
    }
    #[cfg(feature = "std")]
    // Attempt to decode the construction
    if let Ok(path) = env::var(ENV_VAR_TX_LOG_PATH) {
        let mut tx = tx.clone();
        // Contract the large data blobs in the transaction
        tx.wallet_filter();
        // Record the transaction at the identified path
        let mut f = File::options()
            .append(true)
            .create(true)
            .open(path)
            .expect("failed to open test vector file");
        writeln!(f, "{:x?},", tx).expect("unable to write test vector to file");
    }

    (tx, unshielding_epoch)
}

/// Create a wrapper tx from a normal tx. Get the hash of the
/// wrapper and its payload which is needed for monitoring its
/// progress on chain.
pub async fn sign_wrapper<
    'key,
    C: crate::ledger::queries::Client + Sync,
    U: WalletUtils,
    V: ShieldedUtils,
>(
    client: &C,
    wallet: &mut Wallet<U>,
    shielded: &mut ShieldedContext<V>,
    args: &args::Tx,
    epoch: Epoch,
    tx: Tx,
    mut keypair: Cow<'key, common::SecretKey>,
    mut updated_balance: Option<Amount>,
    #[cfg(not(feature = "mainnet"))] requires_pow: bool,
) -> (TxBroadcastData, Option<Epoch>) {
    if args.disposable_signing_key {
        // Create the alias
        let alias_prefix = "disposable_";
        let mut ctr = 1;
        let mut alias = format!("{alias_prefix}_{ctr}");

        while wallet.store().contains_alias(&Alias::from(&alias)) {
            ctr += 1;
            alias = format!("{alias_prefix}_{ctr}");
        }
        // Generate a disposable keypair to sign the wrapper if requested
        // NOTE: this key must be stored in the wallet in case there was the need to resubmit the transaction
        // TODO: once the wrapper transaction has been accepted this key can be deleted from wallet
        let (alias, disposable_keypair) = wallet
            .gen_key(SchemeType::Ed25519, Some(alias), false, None, None)
            .expect("Failed to initialize disposable keypair")
            .expect("Missing alias and secret key");

        tracing::info!("Created disposable keypair with alias {alias}");
        keypair = Cow::Owned(disposable_keypair);
        updated_balance = Some(Amount::default());
    }

    let (mut tx, unshielding_epoch) = wrap_tx(
        client,
        wallet,
        shielded,
        tx,
        args,
        updated_balance,
        epoch,
        &keypair.as_ref().ref_to(),
        #[cfg(not(feature = "mainnet"))]
        requires_pow,
    )
    .await;

    #[cfg(feature = "std")]
    // Attempt to decode the construction
    if let Ok(path) = env::var(ENV_VAR_LEDGER_LOG_PATH) {
        let mut tx = tx.clone();
        // Contract the large data blobs in the transaction
        tx.wallet_filter();
        // Convert the transaction to Ledger format
        let decoding = to_ledger_vector(client, wallet, &tx)
            .await
            .expect("unable to decode transaction");
        let output = serde_json::to_string(&decoding)
            .expect("failed to serialize decoding");
        // Record the transaction at the identified path
        let mut f = File::options()
            .append(true)
            .create(true)
            .open(path)
            .expect("failed to open test vector file");
        writeln!(f, "{},", output)
            .expect("unable to write test vector to file");
    }
    #[cfg(feature = "std")]
    // Attempt to decode the construction
    if let Ok(path) = env::var(ENV_VAR_TX_LOG_PATH) {
        let mut tx = tx.clone();
        // Contract the large data blobs in the transaction
        tx.wallet_filter();
        // Record the transaction at the identified path
        let mut f = File::options()
            .append(true)
            .create(true)
            .open(path)
            .expect("failed to open test vector file");
        writeln!(f, "{:x?},", tx).expect("unable to write test vector to file");
    }

    // Remove all the sensitive sections
    tx.protocol_filter();
    // Then sign over the bound wrapper committing to all other sections
    tx.add_section(Section::Signature(Signature::new(
        tx.sechashes(),
        &keypair,
    )));
    // We use this to determine when the wrapper tx makes it on-chain
    let wrapper_hash = tx.header_hash().to_string();
    // We use this to determine when the decrypted inner tx makes it
    // on-chain
    let decrypted_hash = tx
        .clone()
        .update_header(TxType::Raw)
        .header_hash()
        .to_string();
    let to_broadcast = TxBroadcastData::Live {
        tx,
        wrapper_hash,
        decrypted_hash,
    };

    (to_broadcast, unshielding_epoch)
}

#[allow(clippy::result_large_err)]
fn other_err<T>(string: String) -> Result<T, Error> {
    Err(Error::Other(string))
}

/// Represents the transaction data that is displayed on a Ledger device
#[derive(Default, Serialize, Deserialize)]
pub struct LedgerVector {
    blob: String,
    index: u64,
    name: String,
    output: Vec<String>,
    output_expert: Vec<String>,
    valid: bool,
}

/// Adds a Ledger output line describing a given transaction amount and address
fn make_ledger_amount_addr(
    tokens: &HashMap<Address, String>,
    output: &mut Vec<String>,
    amount: DenominatedAmount,
    token: &Address,
    prefix: &str,
) {
    if let Some(token) = tokens.get(token) {
        output.push(format!("{}Amount {}: {}", prefix, token, amount));
    } else {
        output.extend(vec![
            format!("{}Token: {}", prefix, token),
            format!("{}Amount: {}", prefix, amount),
        ]);
    }
}

/// Adds a Ledger output line describing a given transaction amount and asset
/// type
async fn make_ledger_amount_asset<C: crate::ledger::queries::Client + Sync>(
    client: &C,
    tokens: &HashMap<Address, String>,
    output: &mut Vec<String>,
    amount: u64,
    token: &AssetType,
    assets: &HashMap<AssetType, (Address, MaspDenom, Epoch)>,
    prefix: &str,
) {
    if let Some((token, _, _epoch)) = assets.get(token) {
        // If the AssetType can be decoded, then at least display Addressees
        let formatted_amt =
            format_denominated_amount(client, token, amount.into()).await;
        if let Some(token) = tokens.get(token) {
            output
                .push(
                    format!("{}Amount: {} {}", prefix, token, formatted_amt,),
                );
        } else {
            output.extend(vec![
                format!("{}Token: {}", prefix, token),
                format!("{}Amount: {}", prefix, formatted_amt),
            ]);
        }
    } else {
        // Otherwise display the raw AssetTypes
        output.extend(vec![
            format!("{}Token: {}", prefix, token),
            format!("{}Amount: {}", prefix, amount),
        ]);
    }
}

/// Split the lines in the vector that are longer than the Ledger device's
/// character width
fn format_outputs(output: &mut Vec<String>) {
    const LEDGER_WIDTH: usize = 60;

    let mut i = 0;
    let mut pos = 0;
    // Break down each line that is too long one-by-one
    while pos < output.len() {
        let prefix_len = i.to_string().len() + 3;
        let curr_line = output[pos].clone();
        if curr_line.len() + prefix_len < LEDGER_WIDTH {
            // No need to split the line in this case
            output[pos] = format!("{} | {}", i, curr_line);
            pos += 1;
        } else {
            // Line is too long so split it up. Repeat the key on each line
            let (mut key, mut value) =
                curr_line.split_once(':').unwrap_or(("", &curr_line));
            key = key.trim();
            value = value.trim();
            if value.is_empty() {
                value = "(none)"
            }

            // First comput how many lines we will break the current one up into
            let mut digits = 1;
            let mut line_space;
            let mut lines;
            loop {
                let prefix_len = prefix_len + 7 + 2 * digits + key.len();
                line_space = LEDGER_WIDTH - prefix_len;
                lines = (value.len() + line_space - 1) / line_space;
                if lines.to_string().len() <= digits {
                    break;
                } else {
                    digits += 1;
                }
            }

            // Then break up this line according to the above plan
            output.remove(pos);
            for (idx, part) in
                value.chars().chunks(line_space).into_iter().enumerate()
            {
                let line = format!(
                    "{} | {} [{}/{}] : {}",
                    i,
                    key,
                    idx + 1,
                    lines,
                    part.collect::<String>(),
                );
                output.insert(pos, line);
                pos += 1;
            }
        }
        i += 1;
    }
}

/// Adds a Ledger output for the sender and destination for transparent and MASP
/// transactions
pub async fn make_ledger_masp_endpoints<
    C: crate::ledger::queries::Client + Sync,
>(
    client: &C,
    tokens: &HashMap<Address, String>,
    output: &mut Vec<String>,
    transfer: &Transfer,
    builder: Option<&MaspBuilder>,
    assets: &HashMap<AssetType, (Address, MaspDenom, Epoch)>,
) {
    if transfer.source != masp() {
        output.push(format!("Sender : {}", transfer.source));
        if transfer.target == masp() {
            make_ledger_amount_addr(
                tokens,
                output,
                transfer.amount,
                &transfer.token,
                "Sending ",
            );
        }
    } else if let Some(builder) = builder {
        for sapling_input in builder.builder.sapling_inputs() {
            let vk = ExtendedViewingKey::from(*sapling_input.key());
            output.push(format!("Sender : {}", vk));
            make_ledger_amount_asset(
                client,
                tokens,
                output,
                sapling_input.value(),
                &sapling_input.asset_type(),
                assets,
                "Sending ",
            )
            .await;
        }
    }
    if transfer.target != masp() {
        output.push(format!("Destination : {}", transfer.target));
        if transfer.source == masp() {
            make_ledger_amount_addr(
                tokens,
                output,
                transfer.amount,
                &transfer.token,
                "Receiving ",
            );
        }
    } else if let Some(builder) = builder {
        for sapling_output in builder.builder.sapling_outputs() {
            let pa = PaymentAddress::from(sapling_output.address());
            output.push(format!("Destination : {}", pa));
            make_ledger_amount_asset(
                client,
                tokens,
                output,
                sapling_output.value(),
                &sapling_output.asset_type(),
                assets,
                "Receiving ",
            )
            .await;
        }
    }
    if transfer.source != masp() && transfer.target != masp() {
        make_ledger_amount_addr(
            tokens,
            output,
            transfer.amount,
            &transfer.token,
            "",
        );
    }
}

/// Converts the given transaction to the form that is displayed on the Ledger
/// device
pub async fn to_ledger_vector<
    C: crate::ledger::queries::Client + Sync,
    U: WalletUtils,
>(
    client: &C,
    wallet: &mut Wallet<U>,
    tx: &Tx,
) -> Result<LedgerVector, std::io::Error> {
    let init_account_hash = query_wasm_code_hash(client, TX_INIT_ACCOUNT_WASM)
        .await
        .unwrap();
    let init_validator_hash =
        query_wasm_code_hash(client, TX_INIT_VALIDATOR_WASM)
            .await
            .unwrap();
    let init_proposal_hash = query_wasm_code_hash(client, TX_INIT_PROPOSAL)
        .await
        .unwrap();
    let vote_proposal_hash = query_wasm_code_hash(client, TX_VOTE_PROPOSAL)
        .await
        .unwrap();
    let reveal_pk_hash =
        query_wasm_code_hash(client, TX_REVEAL_PK).await.unwrap();
    let update_vp_hash = query_wasm_code_hash(client, TX_UPDATE_VP_WASM)
        .await
        .unwrap();
    let transfer_hash = query_wasm_code_hash(client, TX_TRANSFER_WASM)
        .await
        .unwrap();
    let ibc_hash = query_wasm_code_hash(client, TX_IBC_WASM).await.unwrap();
    let bond_hash = query_wasm_code_hash(client, TX_BOND_WASM).await.unwrap();
    let unbond_hash =
        query_wasm_code_hash(client, TX_UNBOND_WASM).await.unwrap();
    let withdraw_hash = query_wasm_code_hash(client, TX_WITHDRAW_WASM)
        .await
        .unwrap();
    let change_commission_hash =
        query_wasm_code_hash(client, TX_CHANGE_COMMISSION_WASM)
            .await
            .unwrap();
    let user_hash = query_wasm_code_hash(client, VP_USER_WASM).await.unwrap();

    // To facilitate lookups of human-readable token names
    let tokens: HashMap<Address, String> = wallet
        .get_addresses_with_vp_type(AddressVpType::Token)
        .into_iter()
        .map(|addr| {
            let alias = match wallet.find_alias(&addr) {
                Some(alias) => alias.to_string(),
                None => addr.to_string(),
            };
            (addr, alias)
        })
        .collect();

    let mut tv = LedgerVector {
        blob: HEXLOWER
            .encode(&tx.try_to_vec().expect("unable to serialize transaction")),
        index: 0,
        valid: true,
        name: "Custom 0".to_string(),
        ..Default::default()
    };

    let code_hash = tx
        .get_section(tx.code_sechash())
        .expect("expected tx code section to be present")
        .code_sec()
        .expect("expected section to have code tag")
        .code
        .hash();
    tv.output_expert
        .push(format!("Code hash : {}", HEXLOWER.encode(&code_hash.0)));

    if code_hash == init_account_hash {
        let init_account =
            InitAccount::try_from_slice(&tx.data().ok_or_else(|| {
                std::io::Error::from(ErrorKind::InvalidData)
            })?)?;

        tv.name = "Init Account 0".to_string();

        let extra = tx
            .get_section(&init_account.vp_code_hash)
            .and_then(|x| Section::extra_data_sec(x.as_ref()))
            .expect("unable to load vp code")
            .code
            .hash();
        let vp_code = if extra == user_hash {
            "User".to_string()
        } else {
            HEXLOWER.encode(&extra.0)
        };

        tv.output.extend(vec![
            format!("Type : Init Account"),
            format!("Public key : {}", init_account.public_key),
            format!("VP type : {}", vp_code),
        ]);

        tv.output_expert.extend(vec![
            format!("Public key : {}", init_account.public_key),
            format!("VP type : {}", HEXLOWER.encode(&extra.0)),
        ]);
    } else if code_hash == init_validator_hash {
        let init_validator =
            InitValidator::try_from_slice(&tx.data().ok_or_else(|| {
                std::io::Error::from(ErrorKind::InvalidData)
            })?)?;

        tv.name = "Init Validator 0".to_string();

        let extra = tx
            .get_section(&init_validator.validator_vp_code_hash)
            .and_then(|x| Section::extra_data_sec(x.as_ref()))
            .expect("unable to load vp code")
            .code
            .hash();
        let vp_code = if extra == user_hash {
            "User".to_string()
        } else {
            HEXLOWER.encode(&extra.0)
        };

        tv.output.extend(vec![
            format!("Type : Init Validator"),
            format!("Account key : {}", init_validator.account_key),
            format!("Consensus key : {}", init_validator.consensus_key),
            format!("Protocol key : {}", init_validator.protocol_key),
            format!("DKG key : {}", init_validator.dkg_key),
            format!("Commission rate : {}", init_validator.commission_rate),
            format!(
                "Maximum commission rate change : {}",
                init_validator.max_commission_rate_change
            ),
            format!("Validator VP type : {}", vp_code,),
        ]);

        tv.output_expert.extend(vec![
            format!("Account key : {}", init_validator.account_key),
            format!("Consensus key : {}", init_validator.consensus_key),
            format!("Protocol key : {}", init_validator.protocol_key),
            format!("DKG key : {}", init_validator.dkg_key),
            format!("Commission rate : {}", init_validator.commission_rate),
            format!(
                "Maximum commission rate change : {}",
                init_validator.max_commission_rate_change
            ),
            format!("Validator VP type : {}", HEXLOWER.encode(&extra.0)),
        ]);
    } else if code_hash == init_proposal_hash {
        let init_proposal_data =
            InitProposalData::try_from_slice(&tx.data().ok_or_else(|| {
                std::io::Error::from(ErrorKind::InvalidData)
            })?)?;

        tv.name = "Init Proposal 0".to_string();

        let init_proposal_data_id = init_proposal_data
            .id
            .as_ref()
            .map(u64::to_string)
            .unwrap_or_else(|| "(none)".to_string());
        tv.output.extend(vec![
            format!("Type : Init proposal"),
            format!("ID : {}", init_proposal_data_id),
            format!("Author : {}", init_proposal_data.author),
            format!(
                "Voting start epoch : {}",
                init_proposal_data.voting_start_epoch
            ),
            format!(
                "Voting end epoch : {}",
                init_proposal_data.voting_end_epoch
            ),
            format!("Grace epoch : {}", init_proposal_data.grace_epoch),
        ]);
        tv.output
            .push(format!("Content: {}", init_proposal_data.content));

        tv.output_expert.extend(vec![
            format!("ID : {}", init_proposal_data_id),
            format!("Author : {}", init_proposal_data.author),
            format!(
                "Voting start epoch : {}",
                init_proposal_data.voting_start_epoch
            ),
            format!(
                "Voting end epoch : {}",
                init_proposal_data.voting_end_epoch
            ),
            format!("Grace epoch : {}", init_proposal_data.grace_epoch),
        ]);
        tv.output
            .push(format!("Content: {}", init_proposal_data.content));
    } else if code_hash == vote_proposal_hash {
        let vote_proposal =
            VoteProposalData::try_from_slice(&tx.data().ok_or_else(|| {
                std::io::Error::from(ErrorKind::InvalidData)
            })?)?;

        tv.name = "Vote Proposal 0".to_string();

        tv.output.extend(vec![
            format!("Type : Vote Proposal"),
            format!("ID : {}", vote_proposal.id),
            format!("Vote : {}", vote_proposal.vote),
            format!("Voter : {}", vote_proposal.voter),
        ]);
        for delegation in &vote_proposal.delegations {
            tv.output.push(format!("Delegations : {}", delegation));
        }

        tv.output_expert.extend(vec![
            format!("ID : {}", vote_proposal.id),
            format!("Vote : {}", vote_proposal.vote),
            format!("Voter : {}", vote_proposal.voter),
        ]);
        for delegation in vote_proposal.delegations {
            tv.output_expert
                .push(format!("Delegations : {}", delegation));
        }
    } else if code_hash == reveal_pk_hash {
        let public_key = common::PublicKey::try_from_slice(
            &tx.data()
                .ok_or_else(|| std::io::Error::from(ErrorKind::InvalidData))?,
        )?;

        tv.name = "Init Account 0".to_string();

        tv.output.extend(vec![
            format!("Type : Reveal PK"),
            format!("Public key : {}", public_key),
        ]);

        tv.output_expert
            .extend(vec![format!("Public key : {}", public_key)]);
    } else if code_hash == update_vp_hash {
        let transfer =
            UpdateVp::try_from_slice(&tx.data().ok_or_else(|| {
                std::io::Error::from(ErrorKind::InvalidData)
            })?)?;

        tv.name = "Update VP 0".to_string();

        let extra = tx
            .get_section(&transfer.vp_code_hash)
            .and_then(|x| Section::extra_data_sec(x.as_ref()))
            .expect("unable to load vp code")
            .code
            .hash();
        let vp_code = if extra == user_hash {
            "User".to_string()
        } else {
            HEXLOWER.encode(&extra.0)
        };

        tv.output.extend(vec![
            format!("Type : Update VP"),
            format!("Address : {}", transfer.addr),
            format!("VP type : {}", vp_code),
        ]);

        tv.output_expert.extend(vec![
            format!("Address : {}", transfer.addr),
            format!("VP type : {}", HEXLOWER.encode(&extra.0)),
        ]);
    } else if code_hash == transfer_hash {
        let transfer =
            Transfer::try_from_slice(&tx.data().ok_or_else(|| {
                std::io::Error::from(ErrorKind::InvalidData)
            })?)?;
        // To facilitate lookups of MASP AssetTypes
        let mut asset_types = HashMap::new();
        let builder = if let Some(shielded_hash) = transfer.shielded {
            tx.sections.iter().find_map(|x| match x {
                Section::MaspBuilder(builder)
                    if builder.target == shielded_hash =>
                {
                    for (addr, denom, epoch) in &builder.asset_types {
                        asset_types.insert(
                            make_asset_type(Some(*epoch), addr, *denom),
                            (addr.clone(), *denom, *epoch),
                        );
                    }
                    Some(builder)
                }
                _ => None,
            })
        } else {
            None
        };

        tv.name = "Transfer 0".to_string();

        tv.output.push("Type : Transfer".to_string());
        make_ledger_masp_endpoints(
            client,
            &tokens,
            &mut tv.output,
            &transfer,
            builder,
            &asset_types,
        )
        .await;
        make_ledger_masp_endpoints(
            client,
            &tokens,
            &mut tv.output_expert,
            &transfer,
            builder,
            &asset_types,
        )
        .await;
    } else if code_hash == ibc_hash {
        let msg = Any::decode(
            tx.data()
                .ok_or_else(|| std::io::Error::from(ErrorKind::InvalidData))?
                .as_ref(),
        )
        .map_err(|x| std::io::Error::new(ErrorKind::Other, x))?;

        tv.name = "IBC 0".to_string();
        tv.output.push("Type : IBC".to_string());

        match msg.type_url.as_str() {
            MSG_TRANSFER_TYPE_URL => {
                let transfer = MsgTransfer::try_from(msg).map_err(|_| {
                    std::io::Error::from(ErrorKind::InvalidData)
                })?;
                let transfer_token = format!(
                    "{} {}",
                    transfer.token.amount, transfer.token.denom
                );
                tv.output.extend(vec![
                    format!("Source port : {}", transfer.port_id_on_a),
                    format!("Source channel : {}", transfer.chan_id_on_a),
                    format!("Token : {}", transfer_token),
                    format!("Sender : {}", transfer.sender),
                    format!("Receiver : {}", transfer.receiver),
                    format!(
                        "Timeout height : {}",
                        transfer.timeout_height_on_b
                    ),
                    format!(
                        "Timeout timestamp : {}",
                        transfer.timeout_timestamp_on_b
                    ),
                ]);
                tv.output_expert.extend(vec![
                    format!("Source port : {}", transfer.port_id_on_a),
                    format!("Source channel : {}", transfer.chan_id_on_a),
                    format!("Token : {}", transfer_token),
                    format!("Sender : {}", transfer.sender),
                    format!("Receiver : {}", transfer.receiver),
                    format!(
                        "Timeout height : {}",
                        transfer.timeout_height_on_b
                    ),
                    format!(
                        "Timeout timestamp : {}",
                        transfer.timeout_timestamp_on_b
                    ),
                ]);
            }
            _ => {
                for line in format!("{:#?}", msg).split('\n') {
                    let stripped = line.trim_start();
                    tv.output.push(format!("Part : {}", stripped));
                    tv.output_expert.push(format!("Part : {}", stripped));
                }
            }
        }
    } else if code_hash == bond_hash {
        let bond =
            pos::Bond::try_from_slice(&tx.data().ok_or_else(|| {
                std::io::Error::from(ErrorKind::InvalidData)
            })?)?;

        tv.name = "Bond 0".to_string();

        let bond_source = bond
            .source
            .as_ref()
            .map(Address::to_string)
            .unwrap_or_else(|| "(none)".to_string());
        tv.output.extend(vec![
            format!("Type : Bond"),
            format!("Source : {}", bond_source),
            format!("Validator : {}", bond.validator),
            format!("Amount : {}", bond.amount.to_string_native()),
        ]);

        tv.output_expert.extend(vec![
            format!("Source : {}", bond_source),
            format!("Validator : {}", bond.validator),
            format!("Amount : {}", bond.amount.to_string_native()),
        ]);
    } else if code_hash == unbond_hash {
        let unbond =
            pos::Unbond::try_from_slice(&tx.data().ok_or_else(|| {
                std::io::Error::from(ErrorKind::InvalidData)
            })?)?;

        tv.name = "Unbond 0".to_string();

        let unbond_source = unbond
            .source
            .as_ref()
            .map(Address::to_string)
            .unwrap_or_else(|| "(none)".to_string());
        tv.output.extend(vec![
            format!("Code : Unbond"),
            format!("Source : {}", unbond_source),
            format!("Validator : {}", unbond.validator),
            format!("Amount : {}", unbond.amount.to_string_native()),
        ]);

        tv.output_expert.extend(vec![
            format!("Source : {}", unbond_source),
            format!("Validator : {}", unbond.validator),
            format!("Amount : {}", unbond.amount.to_string_native()),
        ]);
    } else if code_hash == withdraw_hash {
        let withdraw =
            pos::Withdraw::try_from_slice(&tx.data().ok_or_else(|| {
                std::io::Error::from(ErrorKind::InvalidData)
            })?)?;

        tv.name = "Withdraw 0".to_string();

        let withdraw_source = withdraw
            .source
            .as_ref()
            .map(Address::to_string)
            .unwrap_or_else(|| "(none)".to_string());
        tv.output.extend(vec![
            format!("Type : Withdraw"),
            format!("Source : {}", withdraw_source),
            format!("Validator : {}", withdraw.validator),
        ]);

        tv.output_expert.extend(vec![
            format!("Source : {}", withdraw_source),
            format!("Validator : {}", withdraw.validator),
        ]);
    } else if code_hash == change_commission_hash {
        let commission_change = pos::CommissionChange::try_from_slice(
            &tx.data()
                .ok_or_else(|| std::io::Error::from(ErrorKind::InvalidData))?,
        )?;

        tv.name = "Change Commission 0".to_string();

        tv.output.extend(vec![
            format!("Type : Change commission"),
            format!("New rate : {}", commission_change.new_rate),
            format!("Validator : {}", commission_change.validator),
        ]);

        tv.output_expert.extend(vec![
            format!("New rate : {}", commission_change.new_rate),
            format!("Validator : {}", commission_change.validator),
        ]);
    }

    if let Some(wrapper) = tx.header.wrapper() {
        let gas_token = wrapper.fee.token.clone();
        let gas_limit = format_denominated_amount(
            client,
            &gas_token,
            Amount::from(wrapper.gas_limit),
        )
        .await;
        let fee_amount_per_gas_unit = format_denominated_amount(
            client,
            &gas_token,
            wrapper.fee.amount_per_gas_unit,
        )
        .await;
        tv.output_expert.extend(vec![
            format!("Timestamp : {}", tx.header.timestamp.0),
            format!("PK : {}", wrapper.pk),
            format!("Epoch : {}", wrapper.epoch),
            format!("Gas limit : {}", gas_limit),
            format!("Fee token : {}", gas_token),
        ]);
        if let Some(token) = tokens.get(&wrapper.fee.token) {
            tv.output_expert.push(format!(
                "Fee amount per gas unit : {} {}",
                token, fee_amount_per_gas_unit
            ));
        } else {
            tv.output_expert.push(format!(
                "Fee amount per gas unit : {}",
                fee_amount_per_gas_unit
            ));
        }
    }

    // Finally, index each line and break those that are too long
    format_outputs(&mut tv.output);
    format_outputs(&mut tv.output_expert);
    Ok(tv)
}
