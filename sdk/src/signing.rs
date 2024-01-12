//! Functions to sign transactions
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt::Display;

use borsh::BorshDeserialize;
use borsh_ext::BorshSerializeExt;
use data_encoding::HEXLOWER;
use itertools::Itertools;
use masp_primitives::asset_type::AssetType;
use masp_primitives::transaction::components::sapling::fees::{
    InputView, OutputView,
};
use namada_core::ledger::parameters::storage as parameter_storage;
use namada_core::proto::SignatureIndex;
use namada_core::types::account::AccountPublicKeysMap;
use namada_core::types::address::{
    masp_tx_key, Address, ImplicitAddress, InternalAddress, MASP,
};
use namada_core::types::key::*;
use namada_core::types::masp::{ExtendedViewingKey, PaymentAddress};
use namada_core::types::storage::Epoch;
use namada_core::types::token;
use namada_core::types::token::Transfer;
// use namada_core::types::storage::Key;
use namada_core::types::token::{Amount, DenominatedAmount, MaspDenom};
use namada_core::types::transaction::account::{InitAccount, UpdateAccount};
use namada_core::types::transaction::governance::{
    InitProposalData, VoteProposalData,
};
use namada_core::types::transaction::pgf::UpdateStewardCommission;
use namada_core::types::transaction::pos::BecomeValidator;
use namada_core::types::transaction::{pos, Fee};
use prost::Message;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::Digest;
use tokio::sync::RwLock;

use super::masp::{ShieldedContext, ShieldedTransfer};
use crate::args::SdkTypes;
use crate::core::ledger::governance::storage::proposal::ProposalType;
use crate::core::ledger::governance::storage::vote::ProposalVote;
use crate::core::types::eth_bridge_pool::PendingTransfer;
use crate::error::{EncodingError, Error, TxError};
use crate::ibc::apps::transfer::types::msgs::transfer::MsgTransfer;
use crate::ibc::primitives::proto::Any;
use crate::io::*;
use crate::masp::make_asset_type;
use crate::proto::{MaspBuilder, Section, Tx};
use crate::rpc::validate_amount;
use crate::tx::{
    TX_BECOME_VALIDATOR_WASM, TX_BOND_WASM, TX_BRIDGE_POOL_WASM,
    TX_CHANGE_COMMISSION_WASM, TX_CHANGE_CONSENSUS_KEY_WASM,
    TX_CHANGE_METADATA_WASM, TX_CLAIM_REWARDS_WASM,
    TX_DEACTIVATE_VALIDATOR_WASM, TX_IBC_WASM, TX_INIT_ACCOUNT_WASM,
    TX_INIT_PROPOSAL, TX_REACTIVATE_VALIDATOR_WASM, TX_REDELEGATE_WASM,
    TX_RESIGN_STEWARD, TX_REVEAL_PK, TX_TRANSFER_WASM, TX_UNBOND_WASM,
    TX_UNJAIL_VALIDATOR_WASM, TX_UPDATE_ACCOUNT_WASM,
    TX_UPDATE_STEWARD_COMMISSION, TX_VOTE_PROPOSAL, TX_WITHDRAW_WASM,
    VP_USER_WASM,
};
pub use crate::wallet::store::AddressVpType;
use crate::wallet::{Wallet, WalletIo};
use crate::{args, display_line, rpc, MaybeSend, Namada};

/// A structure holding the signing data to craft a transaction
#[derive(Clone)]
pub struct SigningTxData {
    /// The address owning the transaction
    pub owner: Option<Address>,
    /// The public keys associated to an account
    pub public_keys: Vec<common::PublicKey>,
    /// The threshold associated to an account
    pub threshold: u8,
    /// The public keys to index map associated to an account
    pub account_public_keys_map: Option<AccountPublicKeysMap>,
    /// The public keys of the fee payer
    pub fee_payer: common::PublicKey,
}

/// Find the public key for the given address and try to load the keypair
/// for it from the wallet. If the keypair is encrypted but a password is not
/// supplied, then it is interactively prompted. Errors if the key cannot be
/// found or loaded.
pub async fn find_pk(
    context: &impl Namada,
    addr: &Address,
) -> Result<common::PublicKey, Error> {
    match addr {
        Address::Established(_) => {
            display_line!(
                context.io(),
                "Looking-up public key of {} from the ledger...",
                addr.encode()
            );
            rpc::get_public_key_at(context.client(), addr, 0)
                .await?
                .ok_or(Error::Other(format!(
                    "No public key found for the address {}",
                    addr.encode()
                )))
        }
        Address::Implicit(ImplicitAddress(pkh)) => Ok(context
            .wallet_mut()
            .await
            .find_public_key_by_pkh(pkh)
            .map_err(|err| {
                Error::Other(format!(
                    "Unable to load the keypair from the wallet for the \
                     implicit address {}. Failed with: {}",
                    addr.encode(),
                    err
                ))
            })?),
        Address::Internal(_) => other_err(format!(
            "Internal address {} doesn't have any signing keys.",
            addr
        )),
    }
}

/// Load the secret key corresponding to the given public key from the wallet.
/// If the keypair is encrypted but a password is not supplied, then it is
/// interactively prompted. Errors if the key cannot be found or loaded.
pub fn find_key_by_pk<U: WalletIo>(
    wallet: &mut Wallet<U>,
    args: &args::Tx,
    public_key: &common::PublicKey,
) -> Result<common::SecretKey, Error> {
    if *public_key == masp_tx_key().ref_to() {
        // We already know the secret key corresponding to the MASP sentinel key
        Ok(masp_tx_key())
    } else {
        // Otherwise we need to search the wallet for the secret key
        wallet
            .find_key_by_pk(public_key, args.password.clone())
            .map_err(|err| {
                Error::Other(format!(
                    "Unable to load the keypair from the wallet for public \
                     key {}. Failed with: {}",
                    public_key, err
                ))
            })
    }
}

/// Given CLI arguments and some defaults, determine the rightful transaction
/// signer. Return the given signing key or public key of the given signer if
/// possible. If no explicit signer given, use the `default`. If no `default`
/// is given, an `Error` is returned.
pub async fn tx_signers(
    context: &impl Namada,
    args: &args::Tx<SdkTypes>,
    default: Option<Address>,
) -> Result<Vec<common::PublicKey>, Error> {
    let signer = if !&args.signing_keys.is_empty() {
        return Ok(args.signing_keys.clone());
    } else {
        // Otherwise use the signer determined by the caller
        default
    };

    // Now actually fetch the signing key and apply it
    match signer {
        Some(signer) if signer == MASP => Ok(vec![masp_tx_key().ref_to()]),

        Some(signer) => Ok(vec![find_pk(context, &signer).await?]),
        None => other_err(
            "All transactions must be signed; please either specify the key \
             or the address from which to look up the signing key."
                .to_string(),
        ),
    }
}

/// The different parts of a transaction that can be signed
#[derive(Eq, Hash, PartialEq)]
pub enum Signable {
    FeeHeader,
    RawHeader,
}

/// Causes sign_tx to attempt signing using only the software wallet
pub async fn default_sign(
    _tx: Tx,
    pubkey: common::PublicKey,
    _parts: HashSet<Signable>,
    _user: (),
) -> Result<Tx, Error> {
    Err(Error::Other(format!(
        "unable to sign transaction with {}",
        pubkey
    )))
}

/// Sign a transaction with a given signing key or public key of a given signer.
/// If no explicit signer given, use the `default`. If no `default` is given,
/// Error.
///
/// It also takes a second, optional keypair to sign the wrapper header
/// separately.
///
/// If this is not a dry run, the tx is put in a wrapper and returned along with
/// hashes needed for monitoring the tx on chain.
///
/// If it is a dry run, it is not put in a wrapper, but returned as is.
pub async fn sign_tx<'a, D, F, U>(
    wallet: &RwLock<Wallet<U>>,
    args: &args::Tx,
    tx: &mut Tx,
    signing_data: SigningTxData,
    sign: impl Fn(Tx, common::PublicKey, HashSet<Signable>, D) -> F,
    user_data: D,
) -> Result<(), Error>
where
    D: Clone + MaybeSend,
    U: WalletIo,
    F: std::future::Future<Output = Result<Tx, Error>>,
{
    let mut used_pubkeys = HashSet::new();

    // First try to sign the raw header with the supplied signatures
    if !args.signatures.is_empty() {
        let signatures = args
            .signatures
            .iter()
            .map(|bytes| {
                let sigidx = SignatureIndex::deserialize(bytes).unwrap();
                used_pubkeys.insert(sigidx.pubkey.clone());
                sigidx
            })
            .collect();
        tx.add_signatures(signatures);
    }

    // Then try to sign the raw header with private keys in the software wallet
    if let Some(account_public_keys_map) = signing_data.account_public_keys_map
    {
        let mut wallet = wallet.write().await;
        let signing_tx_keypairs = signing_data
            .public_keys
            .iter()
            .filter_map(|public_key| {
                if used_pubkeys.contains(public_key) {
                    None
                } else {
                    match find_key_by_pk(&mut wallet, args, public_key) {
                        Ok(secret_key) => {
                            used_pubkeys.insert(public_key.clone());
                            Some(secret_key)
                        }
                        Err(_) => None,
                    }
                }
            })
            .collect::<Vec<common::SecretKey>>();
        if !signing_tx_keypairs.is_empty() {
            tx.sign_raw(
                signing_tx_keypairs,
                account_public_keys_map,
                signing_data.owner,
            );
        }
    }

    // Then try to sign the raw header using the hardware wallet
    for pubkey in signing_data.public_keys {
        if !used_pubkeys.contains(&pubkey) && pubkey != signing_data.fee_payer {
            if let Ok(ntx) = sign(
                tx.clone(),
                pubkey.clone(),
                HashSet::from([Signable::RawHeader]),
                user_data.clone(),
            )
            .await
            {
                *tx = ntx;
                used_pubkeys.insert(pubkey.clone());
            }
        }
    }

    // Then try signing the fee header with the software wallet otherwise use
    // the fallback
    let key = {
        // Lock the wallet just long enough to extract a key from it without
        // interfering with the sign closure call
        let mut wallet = wallet.write().await;
        find_key_by_pk(&mut *wallet, args, &signing_data.fee_payer)
    };
    match key {
        Ok(fee_payer_keypair) => {
            tx.sign_wrapper(fee_payer_keypair);
        }
        Err(_) => {
            *tx = sign(
                tx.clone(),
                signing_data.fee_payer.clone(),
                HashSet::from([Signable::FeeHeader, Signable::RawHeader]),
                user_data,
            )
            .await?;
        }
    }
    Ok(())
}

/// Return the necessary data regarding an account to be able to generate a
/// multisignature section
pub async fn aux_signing_data(
    context: &impl Namada,
    args: &args::Tx<SdkTypes>,
    owner: Option<Address>,
    default_signer: Option<Address>,
) -> Result<SigningTxData, Error> {
    let public_keys = if owner.is_some() || args.wrapper_fee_payer.is_none() {
        tx_signers(context, args, default_signer.clone()).await?
    } else {
        vec![]
    };

    let (account_public_keys_map, threshold) = match &owner {
        Some(owner @ Address::Established(_)) => {
            let account =
                rpc::get_account_info(context.client(), owner).await?;
            if let Some(account) = account {
                (Some(account.public_keys_map), account.threshold)
            } else {
                return Err(Error::from(TxError::InvalidAccount(
                    owner.encode(),
                )));
            }
        }
        Some(Address::Implicit(_)) => (
            Some(AccountPublicKeysMap::from_iter(public_keys.clone())),
            1u8,
        ),
        Some(owner @ Address::Internal(internal)) => match internal {
            InternalAddress::Masp => (None, 0u8),
            _ => {
                return Err(Error::from(TxError::InvalidAccount(
                    owner.encode(),
                )));
            }
        },
        None => (None, 0u8),
    };

    let fee_payer = if args.disposable_signing_key {
        context
            .wallet_mut()
            .await
            .gen_disposable_signing_key(&mut OsRng)
            .to_public()
    } else {
        match &args.wrapper_fee_payer {
            Some(keypair) => keypair.clone(),
            None => public_keys.get(0).ok_or(TxError::InvalidFeePayer)?.clone(),
        }
    };

    if fee_payer == masp_tx_key().to_public() {
        other_err(
            "The gas payer cannot be the MASP, please provide a different gas \
             payer."
                .to_string(),
        )?;
    }

    Ok(SigningTxData {
        owner,
        public_keys,
        threshold,
        account_public_keys_map,
        fee_payer,
    })
}

pub async fn init_validator_signing_data(
    context: &impl Namada,
    args: &args::Tx<SdkTypes>,
    validator_keys: Vec<common::PublicKey>,
) -> Result<SigningTxData, Error> {
    let mut public_keys = if args.wrapper_fee_payer.is_none() {
        tx_signers(context, args, None).await?
    } else {
        vec![]
    };
    public_keys.extend(validator_keys.clone());

    let account_public_keys_map =
        Some(AccountPublicKeysMap::from_iter(validator_keys));

    let fee_payer = if args.disposable_signing_key {
        context
            .wallet_mut()
            .await
            .gen_disposable_signing_key(&mut OsRng)
            .to_public()
    } else {
        match &args.wrapper_fee_payer {
            Some(keypair) => keypair.clone(),
            None => public_keys.get(0).ok_or(TxError::InvalidFeePayer)?.clone(),
        }
    };

    if fee_payer == masp_tx_key().to_public() {
        other_err(
            "The gas payer cannot be the MASP, please provide a different gas \
             payer."
                .to_string(),
        )?;
    }

    Ok(SigningTxData {
        owner: None,
        public_keys,
        threshold: 0,
        account_public_keys_map,
        fee_payer,
    })
}

/// Information about the post-tx balance of the tx's source. Used to correctly
/// handle fee validation in the wrapper tx
pub struct TxSourcePostBalance {
    /// The balance of the tx source after the tx has been applied
    pub post_balance: Amount,
    /// The source address of the tx
    pub source: Address,
    /// The token of the tx
    pub token: Address,
}

/// Create a wrapper tx from a normal tx. Get the hash of the
/// wrapper and its payload which is needed for monitoring its
/// progress on chain.
#[allow(clippy::too_many_arguments)]
pub async fn wrap_tx<N: Namada>(
    context: &N,
    tx: &mut Tx,
    args: &args::Tx<SdkTypes>,
    tx_source_balance: Option<TxSourcePostBalance>,
    epoch: Epoch,
    fee_payer: common::PublicKey,
) -> Result<(), Error> {
    let fee_payer_address = Address::from(&fee_payer);
    // Validate fee amount and token
    let gas_cost_key = parameter_storage::get_gas_cost_key();
    let minimum_fee = match rpc::query_storage_value::<
        _,
        BTreeMap<Address, Amount>,
    >(context.client(), &gas_cost_key)
    .await
    .and_then(|map| {
        map.get(&args.fee_token)
            .map(ToOwned::to_owned)
            .ok_or_else(|| {
                Error::Other(format!(
                    "Could not retrieve from storage the gas cost for token {}",
                    args.fee_token
                ))
            })
    }) {
        Ok(amount) => amount,
        Err(e) => {
            if !args.force {
                return Err(e);
            } else {
                token::Amount::zero()
            }
        }
    };
    let validated_minimum_fee = context
        .denominate_amount(&args.fee_token, minimum_fee)
        .await;
    let fee_amount = match args.fee_amount {
        Some(amount) => {
            let validated_fee_amount =
                validate_amount(context, amount, &args.fee_token, args.force)
                    .await
                    .expect("Expected to be able to validate fee");

            if validated_fee_amount >= validated_minimum_fee {
                validated_fee_amount
            } else if !args.force {
                // Update the fee amount if it's not enough
                display_line!(
                    context.io(),
                    "The provided gas price {} is less than the minimum \
                     amount required {}, changing it to match the minimum",
                    validated_fee_amount.to_string(),
                    validated_minimum_fee.to_string()
                );
                validated_minimum_fee
            } else {
                validated_fee_amount
            }
        }
        None => validated_minimum_fee,
    };

    let mut updated_balance = match tx_source_balance {
        Some(TxSourcePostBalance {
            post_balance: balance,
            source,
            token,
        }) if token == args.fee_token && source == fee_payer_address => balance,
        _ => {
            let balance_key =
                token::balance_key(&args.fee_token, &fee_payer_address);

            rpc::query_storage_value::<_, token::Amount>(
                context.client(),
                &balance_key,
            )
            .await
            .unwrap_or_default()
        }
    };

    let total_fee = fee_amount.amount() * u64::from(args.gas_limit);

    let unshield = match total_fee.checked_sub(updated_balance) {
        Some(diff) if !diff.is_zero() => {
            if let Some(spending_key) = args.fee_unshield.clone() {
                // Unshield funds for fee payment
                let target = namada_core::types::masp::TransferTarget::Address(
                    fee_payer_address.clone(),
                );
                let fee_amount = DenominatedAmount::new(
                    // NOTE: must unshield the total fee amount, not the
                    // diff, because the ledger evaluates the transaction in
                    // reverse (wrapper first, inner second) and cannot know
                    // ahead of time if the inner will modify the balance of
                    // the gas payer
                    total_fee,
                    0.into(),
                );

                match ShieldedContext::<N::ShieldedUtils>::gen_shielded_transfer(
                        context,
                        &spending_key,
                        &target,
                        &args.fee_token,
                        fee_amount,
                    )
                    .await
                {
                    Ok(Some(ShieldedTransfer {
                        builder: _,
                        masp_tx: transaction,
                        metadata: _data,
                        epoch: _unshielding_epoch,
                    })) => {
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

                        let descriptions = spends + converts + outs;

                        let descriptions_limit_key=  parameter_storage::get_fee_unshielding_descriptions_limit_key();
                        let descriptions_limit =
                            rpc::query_storage_value::<_, u64>(
                                context.client(),
                                &descriptions_limit_key,
                            )
                            .await
                            .unwrap();

                        if u64::try_from(descriptions).unwrap()
                            > descriptions_limit
                            && !args.force
                        {
                            return Err(Error::from(
                                TxError::FeeUnshieldingError(format!(
                                    "Descriptions exceed the limit: found \
                                     {descriptions}, limit \
                                     {descriptions_limit}"
                                )),
                            ));
                        }

                        updated_balance += total_fee;
                        Some(transaction)
                    }
                    Ok(None) => {
                        if !args.force {
                            return Err(Error::from(
                                TxError::FeeUnshieldingError(
                                    "Missing unshielding transaction"
                                        .to_string(),
                                ),
                            ));
                        }

                        None
                    }
                    Err(e) => {
                        if !args.force {
                            return Err(Error::from(
                                TxError::FeeUnshieldingError(e.to_string()),
                            ));
                        }

                        None
                    }
                }
            } else {
                let token_addr = args.fee_token.clone();
                if !args.force {
                    let fee_amount =
                        context.format_amount(&token_addr, total_fee).await;

                    let balance = context
                        .format_amount(&token_addr, updated_balance)
                        .await;
                    return Err(Error::from(TxError::BalanceTooLowForFees(
                        fee_payer_address,
                        token_addr,
                        fee_amount,
                        balance,
                    )));
                }

                None
            }
        }
        _ => {
            if args.fee_unshield.is_some() {
                display_line!(
                    context.io(),
                    "Enough transparent balance to pay fees: the fee \
                     unshielding spending key will be ignored"
                );
            }
            None
        }
    };

    let unshield_section_hash = unshield.map(|masp_tx| {
        let section = Section::MaspTx(masp_tx);
        let mut hasher = sha2::Sha256::new();
        section.hash(&mut hasher);
        tx.add_section(section);
        namada_core::types::hash::Hash(hasher.finalize().into())
    });

    tx.add_wrapper(
        Fee {
            amount_per_gas_unit: fee_amount,
            token: args.fee_token.clone(),
        },
        fee_payer,
        epoch,
        // TODO: partially validate the gas limit in client
        args.gas_limit,
        unshield_section_hash,
    );

    Ok(())
}

#[allow(clippy::result_large_err)]
fn other_err<T>(string: String) -> Result<T, Error> {
    Err(Error::Other(string))
}

/// Represents the transaction data that is displayed on a Ledger device
#[derive(Default, Serialize, Deserialize, Debug, Clone)]
pub struct LedgerVector {
    pub blob: String,
    pub index: u64,
    pub name: String,
    pub output: Vec<String>,
    pub output_expert: Vec<String>,
    pub valid: bool,
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
        output.push(format!(
            "{}Amount : {} {}",
            prefix,
            token.to_uppercase(),
            to_ledger_decimal(&amount.to_string()),
        ));
    } else {
        output.extend(vec![
            format!("{}Token : {}", prefix, token),
            format!(
                "{}Amount : {}",
                prefix,
                to_ledger_decimal(&amount.to_string())
            ),
        ]);
    }
}

/// Adds a Ledger output line describing a given transaction amount and asset
/// type
async fn make_ledger_amount_asset(
    tokens: &HashMap<Address, String>,
    output: &mut Vec<String>,
    amount: u64,
    token: &AssetType,
    assets: &HashMap<AssetType, (Address, MaspDenom, Epoch)>,
    prefix: &str,
) {
    if let Some((token, _, _epoch)) = assets.get(token) {
        // If the AssetType can be decoded, then at least display Addressees
        if let Some(token) = tokens.get(token) {
            output.push(format!(
                "{}Amount : {} {}",
                prefix,
                token.to_uppercase(),
                amount,
            ));
        } else {
            output.extend(vec![
                format!("{}Token : {}", prefix, token),
                format!("{}Amount : {}", prefix, amount,),
            ]);
        }
    } else {
        // Otherwise display the raw AssetTypes
        output.extend(vec![
            format!("{}Token : {}", prefix, token),
            format!(
                "{}Amount : {}",
                prefix,
                to_ledger_decimal(&amount.to_string())
            ),
        ]);
    }
}

/// Split the lines in the vector that are longer than the Ledger device's
/// character width
fn format_outputs(output: &mut Vec<String>) {
    const MAX_KEY_LEN: usize = 39;
    const MAX_VALUE_LEN: usize = 39;

    let mut i = 0;
    let mut pos = 0;
    // Break down each line that is too long one-by-one
    while pos < output.len() {
        let curr_line = output[pos].clone();
        let (key, mut value) =
            curr_line.split_once(':').unwrap_or(("", &curr_line));
        // Truncate the key length to the declared maximum
        let key = key.trim().chars().take(MAX_KEY_LEN - 1).collect::<String>();
        // Trim value because we will insert spaces later
        value = value.trim();
        if value.is_empty() {
            value = "(none)"
        }
        if value.chars().count() < MAX_VALUE_LEN {
            // No need to split the line in this case
            output[pos] = format!("{} | {} : {}", i, key, value);
            pos += 1;
        } else {
            // Line is too long so split it up. Repeat the key on each line
            output.remove(pos);
            let part_count = (value.chars().count() + MAX_VALUE_LEN - 2)
                / (MAX_VALUE_LEN - 1);
            for (idx, part) in value
                .chars()
                .chunks(MAX_VALUE_LEN - 1)
                .into_iter()
                .enumerate()
            {
                let line = format!(
                    "{} | {} [{}/{}] : {}",
                    i,
                    key,
                    idx + 1,
                    part_count,
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
pub async fn make_ledger_masp_endpoints(
    tokens: &HashMap<Address, String>,
    output: &mut Vec<String>,
    transfer: &Transfer,
    builder: Option<&MaspBuilder>,
    assets: &HashMap<AssetType, (Address, MaspDenom, Epoch)>,
) {
    if transfer.source != MASP {
        output.push(format!("Sender : {}", transfer.source));
        if transfer.target == MASP {
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
    if transfer.target != MASP {
        output.push(format!("Destination : {}", transfer.target));
        if transfer.source == MASP {
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
    if transfer.source != MASP && transfer.target != MASP {
        make_ledger_amount_addr(
            tokens,
            output,
            transfer.amount,
            &transfer.token,
            "",
        );
    }
}

/// Convert decimal numbers into the format used by Ledger. Specifically remove
/// all insignificant zeros occurring after decimal point.
fn to_ledger_decimal(amount: &str) -> String {
    if amount.contains('.') {
        let mut amount = amount.trim_end_matches('0').to_string();
        if amount.ends_with('.') {
            amount.push('0')
        }
        amount
    } else {
        amount.to_string() + ".0"
    }
}

/// A ProposalVote wrapper that prints the spending cap with Ledger decimal
/// formatting.
struct LedgerProposalVote<'a>(&'a ProposalVote);

impl<'a> Display for LedgerProposalVote<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.0 {
            ProposalVote::Yay => write!(f, "yay"),
            ProposalVote::Nay => write!(f, "nay"),
            ProposalVote::Abstain => write!(f, "abstain"),
        }
    }
}

/// A ProposalType wrapper that prints the hash of the contained WASM code if it
/// is present.
struct LedgerProposalType<'a>(&'a ProposalType, &'a Tx);

impl<'a> Display for LedgerProposalType<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self.0 {
            ProposalType::Default(None) => write!(f, "Default"),
            ProposalType::Default(Some(hash)) => {
                let extra = self
                    .1
                    .get_section(hash)
                    .and_then(|x| Section::extra_data_sec(x.as_ref()))
                    .expect("unable to load vp code")
                    .code
                    .hash();
                write!(f, "{}", HEXLOWER.encode(&extra.0))
            }
            ProposalType::PGFSteward(_) => write!(f, "PGF Steward"),
            ProposalType::PGFPayment(_) => write!(f, "PGF Payment"),
        }
    }
}

/// Converts the given transaction to the form that is displayed on the Ledger
/// device
pub async fn to_ledger_vector(
    wallet: &Wallet<impl WalletIo>,
    tx: &Tx,
) -> Result<LedgerVector, Error> {
    // To facilitate lookups of human-readable token names
    let tokens: HashMap<Address, String> = wallet
        .get_addresses()
        .into_iter()
        .map(|(alias, addr)| (addr, alias))
        .collect();

    let mut tv = LedgerVector {
        blob: HEXLOWER.encode(&tx.serialize_to_vec()),
        index: 0,
        valid: true,
        name: "Custom_0".to_string(),
        ..Default::default()
    };

    let code_sec = tx
        .get_section(tx.code_sechash())
        .ok_or_else(|| {
            Error::Other("expected tx code section to be present".to_string())
        })?
        .code_sec()
        .ok_or_else(|| {
            Error::Other("expected section to have code tag".to_string())
        })?;
    tv.output_expert.push(format!(
        "Code hash : {}",
        HEXLOWER.encode(&code_sec.code.hash().0)
    ));

    if code_sec.tag == Some(TX_INIT_ACCOUNT_WASM.to_string()) {
        let init_account = InitAccount::try_from_slice(
            &tx.data()
                .ok_or_else(|| Error::Other("Invalid Data".to_string()))?,
        )
        .map_err(|err| {
            Error::from(EncodingError::Conversion(err.to_string()))
        })?;
        tv.name = "Init_Account_0".to_string();

        let extra = tx
            .get_section(&init_account.vp_code_hash)
            .and_then(|x| Section::extra_data_sec(x.as_ref()))
            .ok_or_else(|| {
                Error::Other("unable to load vp code".to_string())
            })?;
        let vp_code = if extra.tag == Some(VP_USER_WASM.to_string()) {
            "User".to_string()
        } else {
            HEXLOWER.encode(&extra.code.hash().0)
        };
        tv.output.extend(vec![format!("Type : Init Account")]);
        tv.output.extend(
            init_account
                .public_keys
                .iter()
                .map(|k| format!("Public key : {}", k)),
        );
        tv.output.extend(vec![
            format!("Threshold : {}", init_account.threshold),
            format!("VP type : {}", vp_code),
        ]);

        tv.output_expert.extend(
            init_account
                .public_keys
                .iter()
                .map(|k| format!("Public key : {}", k)),
        );
        tv.output_expert.extend(vec![
            format!("Threshold : {}", init_account.threshold),
            format!("VP type : {}", HEXLOWER.encode(&extra.code.hash().0)),
        ]);
    } else if code_sec.tag == Some(TX_BECOME_VALIDATOR_WASM.to_string()) {
        let init_validator = BecomeValidator::try_from_slice(
            &tx.data()
                .ok_or_else(|| Error::Other("Invalid Data".to_string()))?,
        )
        .map_err(|err| {
            Error::from(EncodingError::Conversion(err.to_string()))
        })?;

        tv.name = "Init_Validator_0".to_string();

        tv.output.extend(vec!["Type : Init Validator".to_string()]);
        tv.output.extend(vec![
            format!("Address : {}", init_validator.address),
            format!("Consensus key : {}", init_validator.consensus_key),
            format!("Ethereum cold key : {}", init_validator.eth_cold_key),
            format!("Ethereum hot key : {}", init_validator.eth_hot_key),
            format!("Protocol key : {}", init_validator.protocol_key),
            format!("Commission rate : {}", init_validator.commission_rate),
            format!(
                "Maximum commission rate change : {}",
                init_validator.max_commission_rate_change,
            ),
            format!("Email : {}", init_validator.email),
        ]);
        if let Some(description) = &init_validator.description {
            tv.output.push(format!("Description : {}", description));
        }
        if let Some(website) = &init_validator.website {
            tv.output.push(format!("Website : {}", website));
        }
        if let Some(discord_handle) = &init_validator.discord_handle {
            tv.output
                .push(format!("Discord handle : {}", discord_handle));
        }

        tv.output_expert.extend(vec![
            format!("Address : {}", init_validator.address),
            format!("Consensus key : {}", init_validator.consensus_key),
            format!("Ethereum cold key : {}", init_validator.eth_cold_key),
            format!("Ethereum hot key : {}", init_validator.eth_hot_key),
            format!("Protocol key : {}", init_validator.protocol_key),
            format!("Commission rate : {}", init_validator.commission_rate),
            format!(
                "Maximum commission rate change : {}",
                init_validator.max_commission_rate_change
            ),
            format!("Email : {}", init_validator.email),
        ]);
        if let Some(description) = &init_validator.description {
            tv.output_expert
                .push(format!("Description : {}", description));
        }
        if let Some(website) = &init_validator.website {
            tv.output_expert.push(format!("Website : {}", website));
        }
        if let Some(discord_handle) = &init_validator.discord_handle {
            tv.output_expert
                .push(format!("Discord handle : {}", discord_handle));
        }
    } else if code_sec.tag == Some(TX_INIT_PROPOSAL.to_string()) {
        let init_proposal_data = InitProposalData::try_from_slice(
            &tx.data()
                .ok_or_else(|| Error::Other("Invalid Data".to_string()))?,
        )
        .map_err(|err| {
            Error::from(EncodingError::Conversion(err.to_string()))
        })?;

        tv.name = "Init_Proposal_0".to_string();

        let extra = tx
            .get_section(&init_proposal_data.content)
            .and_then(|x| Section::extra_data_sec(x.as_ref()))
            .expect("unable to load vp code")
            .code
            .hash();

        tv.output.push("Type : Init proposal".to_string());
        if let Some(id) = init_proposal_data.id.as_ref() {
            tv.output.push(format!("ID : {}", id));
        }
        tv.output.extend(vec![
            format!(
                "Proposal type : {}",
                LedgerProposalType(&init_proposal_data.r#type, tx)
            ),
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
            format!("Content : {}", HEXLOWER.encode(&extra.0)),
        ]);

        if let Some(id) = init_proposal_data.id.as_ref() {
            tv.output_expert.push(format!("ID : {}", id));
        }
        tv.output_expert.extend(vec![
            format!(
                "Proposal type : {}",
                LedgerProposalType(&init_proposal_data.r#type, tx)
            ),
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
            format!("Content : {}", HEXLOWER.encode(&extra.0)),
        ]);
    } else if code_sec.tag == Some(TX_VOTE_PROPOSAL.to_string()) {
        let vote_proposal = VoteProposalData::try_from_slice(
            &tx.data()
                .ok_or_else(|| Error::Other("Invalid Data".to_string()))?,
        )
        .map_err(|err| {
            Error::from(EncodingError::Conversion(err.to_string()))
        })?;

        tv.name = "Vote_Proposal_0".to_string();

        tv.output.extend(vec![
            format!("Type : Vote Proposal"),
            format!("ID : {}", vote_proposal.id),
            format!("Vote : {}", LedgerProposalVote(&vote_proposal.vote)),
            format!("Voter : {}", vote_proposal.voter),
        ]);
        for delegation in &vote_proposal.delegations {
            tv.output.push(format!("Delegation : {}", delegation));
        }

        tv.output_expert.extend(vec![
            format!("ID : {}", vote_proposal.id),
            format!("Vote : {}", LedgerProposalVote(&vote_proposal.vote)),
            format!("Voter : {}", vote_proposal.voter),
        ]);
        for delegation in vote_proposal.delegations {
            tv.output_expert
                .push(format!("Delegation : {}", delegation));
        }
    } else if code_sec.tag == Some(TX_REVEAL_PK.to_string()) {
        let public_key = common::PublicKey::try_from_slice(
            &tx.data()
                .ok_or_else(|| Error::Other("Invalid Data".to_string()))?,
        )
        .map_err(|err| {
            Error::from(EncodingError::Conversion(err.to_string()))
        })?;

        tv.name = "Reveal_Pubkey_0".to_string();

        tv.output.extend(vec![
            format!("Type : Reveal Pubkey"),
            format!("Public key : {}", public_key),
        ]);

        tv.output_expert
            .extend(vec![format!("Public key : {}", public_key)]);
    } else if code_sec.tag == Some(TX_UPDATE_ACCOUNT_WASM.to_string()) {
        let update_account = UpdateAccount::try_from_slice(
            &tx.data()
                .ok_or_else(|| Error::Other("Invalid Data".to_string()))?,
        )
        .map_err(|err| {
            Error::from(EncodingError::Conversion(err.to_string()))
        })?;

        tv.name = "Update_Account_0".to_string();
        tv.output.extend(vec![
            format!("Type : Update Account"),
            format!("Address : {}", update_account.addr),
        ]);
        tv.output.extend(
            update_account
                .public_keys
                .iter()
                .map(|k| format!("Public key : {}", k)),
        );
        if update_account.threshold.is_some() {
            tv.output.extend(vec![format!(
                "Threshold : {}",
                update_account.threshold.unwrap()
            )])
        }

        let vp_code_data = match &update_account.vp_code_hash {
            Some(hash) => {
                let extra = tx
                    .get_section(hash)
                    .and_then(|x| Section::extra_data_sec(x.as_ref()))
                    .ok_or_else(|| {
                        Error::Other("unable to load vp code".to_string())
                    })?;
                let vp_code = if extra.tag == Some(VP_USER_WASM.to_string()) {
                    "User".to_string()
                } else {
                    HEXLOWER.encode(&extra.code.hash().0)
                };
                Some((vp_code, extra.code.hash()))
            }
            None => None,
        };
        if let Some((vp_code, _)) = &vp_code_data {
            tv.output.extend(vec![format!("VP type : {}", vp_code)]);
        }
        tv.output_expert
            .extend(vec![format!("Address : {}", update_account.addr)]);
        tv.output_expert.extend(
            update_account
                .public_keys
                .iter()
                .map(|k| format!("Public key : {}", k)),
        );
        if let Some(threshold) = update_account.threshold {
            tv.output_expert
                .extend(vec![format!("Threshold : {}", threshold,)])
        }
        if let Some((_, extra_code_hash)) = vp_code_data {
            tv.output_expert.extend(vec![format!(
                "VP type : {}",
                HEXLOWER.encode(&extra_code_hash.0)
            )]);
        }
    } else if code_sec.tag == Some(TX_TRANSFER_WASM.to_string()) {
        let transfer = Transfer::try_from_slice(
            &tx.data()
                .ok_or_else(|| Error::Other("Invalid Data".to_string()))?,
        )
        .map_err(|err| {
            Error::from(EncodingError::Conversion(err.to_string()))
        })?;
        // To facilitate lookups of MASP AssetTypes
        let mut asset_types = HashMap::new();
        let builder = if let Some(shielded_hash) = transfer.shielded {
            tx.sections.iter().find_map(|x| match x {
                Section::MaspBuilder(builder)
                    if builder.target == shielded_hash =>
                {
                    for (addr, denom, epoch) in &builder.asset_types {
                        match make_asset_type(Some(*epoch), addr, *denom) {
                            Err(_) => None,
                            Ok(asset) => {
                                asset_types.insert(
                                    asset,
                                    (addr.clone(), *denom, *epoch),
                                );
                                Some(builder)
                            }
                        }?;
                    }
                    Some(builder)
                }
                _ => None,
            })
        } else {
            None
        };

        tv.name = "Transfer_0".to_string();

        tv.output.push("Type : Transfer".to_string());
        make_ledger_masp_endpoints(
            &tokens,
            &mut tv.output,
            &transfer,
            builder,
            &asset_types,
        )
        .await;
        make_ledger_masp_endpoints(
            &tokens,
            &mut tv.output_expert,
            &transfer,
            builder,
            &asset_types,
        )
        .await;
    } else if code_sec.tag == Some(TX_IBC_WASM.to_string()) {
        let any_msg = Any::decode(
            tx.data()
                .ok_or_else(|| Error::Other("Invalid Data".to_string()))?
                .as_ref(),
        )
        .map_err(|x| Error::from(EncodingError::Conversion(x.to_string())))?;

        tv.name = "IBC_0".to_string();
        tv.output.push("Type : IBC".to_string());

        match MsgTransfer::try_from(any_msg.clone()) {
            Ok(transfer) => {
                let transfer_token = format!(
                    "{} {}",
                    transfer.packet_data.token.amount,
                    transfer.packet_data.token.denom
                );
                tv.output.extend(vec![
                    format!("Source port : {}", transfer.port_id_on_a),
                    format!("Source channel : {}", transfer.chan_id_on_a),
                    format!("Token : {}", transfer_token),
                    format!("Sender : {}", transfer.packet_data.sender),
                    format!("Receiver : {}", transfer.packet_data.receiver),
                    format!(
                        "Timeout height : {}",
                        transfer.timeout_height_on_b
                    ),
                    format!(
                        "Timeout timestamp : {}",
                        transfer
                            .timeout_timestamp_on_b
                            .into_tm_time()
                            .map_or("(none)".to_string(), |time| time
                                .to_rfc3339())
                    ),
                ]);
                tv.output_expert.extend(vec![
                    format!("Source port : {}", transfer.port_id_on_a),
                    format!("Source channel : {}", transfer.chan_id_on_a),
                    format!("Token : {}", transfer_token),
                    format!("Sender : {}", transfer.packet_data.sender),
                    format!("Receiver : {}", transfer.packet_data.receiver),
                    format!(
                        "Timeout height : {}",
                        transfer.timeout_height_on_b
                    ),
                    format!(
                        "Timeout timestamp : {}",
                        transfer
                            .timeout_timestamp_on_b
                            .into_tm_time()
                            .map_or("(none)".to_string(), |time| time
                                .to_rfc3339())
                    ),
                ]);
            }
            _ => {
                for line in format!("{:#?}", any_msg).split('\n') {
                    let stripped = line.trim_start();
                    tv.output.push(format!("Part : {}", stripped));
                    tv.output_expert.push(format!("Part : {}", stripped));
                }
            }
        }
    } else if code_sec.tag == Some(TX_BOND_WASM.to_string()) {
        let bond = pos::Bond::try_from_slice(
            &tx.data()
                .ok_or_else(|| Error::Other("Invalid Data".to_string()))?,
        )
        .map_err(|err| {
            Error::from(EncodingError::Conversion(err.to_string()))
        })?;

        tv.name = "Bond_0".to_string();

        tv.output.push("Type : Bond".to_string());
        if let Some(source) = bond.source.as_ref() {
            tv.output.push(format!("Source : {}", source));
        }
        tv.output.extend(vec![
            format!("Validator : {}", bond.validator),
            format!(
                "Amount : NAM {}",
                to_ledger_decimal(&bond.amount.to_string_native())
            ),
        ]);

        if let Some(source) = bond.source.as_ref() {
            tv.output_expert.push(format!("Source : {}", source));
        }
        tv.output_expert.extend(vec![
            format!("Validator : {}", bond.validator),
            format!(
                "Amount : NAM {}",
                to_ledger_decimal(&bond.amount.to_string_native())
            ),
        ]);
    } else if code_sec.tag == Some(TX_UNBOND_WASM.to_string()) {
        let unbond = pos::Unbond::try_from_slice(
            &tx.data()
                .ok_or_else(|| Error::Other("Invalid Data".to_string()))?,
        )
        .map_err(|err| {
            Error::from(EncodingError::Conversion(err.to_string()))
        })?;

        tv.name = "Unbond_0".to_string();

        tv.output.push("Type : Unbond".to_string());
        if let Some(source) = unbond.source.as_ref() {
            tv.output.push(format!("Source : {}", source));
        }
        tv.output.extend(vec![
            format!("Validator : {}", unbond.validator),
            format!(
                "Amount : NAM {}",
                to_ledger_decimal(&unbond.amount.to_string_native())
            ),
        ]);

        if let Some(source) = unbond.source.as_ref() {
            tv.output_expert.push(format!("Source : {}", source));
        }
        tv.output_expert.extend(vec![
            format!("Validator : {}", unbond.validator),
            format!(
                "Amount : NAM {}",
                to_ledger_decimal(&unbond.amount.to_string_native())
            ),
        ]);
    } else if code_sec.tag == Some(TX_WITHDRAW_WASM.to_string()) {
        let withdraw = pos::Withdraw::try_from_slice(
            &tx.data()
                .ok_or_else(|| Error::Other("Invalid Data".to_string()))?,
        )
        .map_err(|err| {
            Error::from(EncodingError::Conversion(err.to_string()))
        })?;

        tv.name = "Withdraw_0".to_string();

        tv.output.push("Type : Withdraw".to_string());
        if let Some(source) = withdraw.source.as_ref() {
            tv.output.push(format!("Source : {}", source));
        }
        tv.output
            .push(format!("Validator : {}", withdraw.validator));

        if let Some(source) = withdraw.source.as_ref() {
            tv.output_expert.push(format!("Source : {}", source));
        }
        tv.output_expert
            .push(format!("Validator : {}", withdraw.validator));
    } else if code_sec.tag == Some(TX_CLAIM_REWARDS_WASM.to_string()) {
        let claim = pos::Withdraw::try_from_slice(
            &tx.data()
                .ok_or_else(|| Error::Other("Invalid Data".to_string()))?,
        )
        .map_err(|err| {
            Error::from(EncodingError::Conversion(err.to_string()))
        })?;

        tv.name = "Claim_Rewards_0".to_string();

        tv.output.push("Type : Claim Rewards".to_string());
        if let Some(source) = claim.source.as_ref() {
            tv.output.push(format!("Source : {}", source));
        }
        tv.output.push(format!("Validator : {}", claim.validator));

        if let Some(source) = claim.source.as_ref() {
            tv.output_expert.push(format!("Source : {}", source));
        }
        tv.output_expert
            .push(format!("Validator : {}", claim.validator));
    } else if code_sec.tag == Some(TX_CHANGE_COMMISSION_WASM.to_string()) {
        let commission_change = pos::CommissionChange::try_from_slice(
            &tx.data()
                .ok_or_else(|| Error::Other("Invalid Data".to_string()))?,
        )
        .map_err(|err| {
            Error::from(EncodingError::Conversion(err.to_string()))
        })?;

        tv.name = "Change_Commission_0".to_string();

        tv.output.extend(vec![
            format!("Type : Change commission"),
            format!("New rate : {}", commission_change.new_rate),
            format!("Validator : {}", commission_change.validator),
        ]);

        tv.output_expert.extend(vec![
            format!("New rate : {}", commission_change.new_rate),
            format!("Validator : {}", commission_change.validator),
        ]);
    } else if code_sec.tag == Some(TX_CHANGE_METADATA_WASM.to_string()) {
        let metadata_change = pos::MetaDataChange::try_from_slice(
            &tx.data()
                .ok_or_else(|| Error::Other("Invalid Data".to_string()))?,
        )
        .map_err(|err| {
            Error::from(EncodingError::Conversion(err.to_string()))
        })?;

        tv.name = "Change_MetaData_0".to_string();

        tv.output.extend(vec!["Type : Change metadata".to_string()]);

        let mut other_items = vec![];
        if let Some(email) = metadata_change.email {
            other_items.push(format!("New email : {}", email));
        }
        if let Some(description) = metadata_change.description {
            if description.is_empty() {
                other_items.push("Description removed".to_string());
            } else {
                other_items.push(format!("New description : {}", description));
            }
        }
        if let Some(website) = metadata_change.website {
            if website.is_empty() {
                other_items.push("Website removed".to_string());
            } else {
                other_items.push(format!("New website : {}", website));
            }
        }
        if let Some(discord_handle) = metadata_change.discord_handle {
            if discord_handle.is_empty() {
                other_items.push("Discord handle removed".to_string());
            } else {
                other_items
                    .push(format!("New discord handle : {}", discord_handle));
            }
        }

        tv.output.extend(other_items.clone());
        tv.output_expert.extend(other_items);
    } else if code_sec.tag == Some(TX_CHANGE_CONSENSUS_KEY_WASM.to_string()) {
        let consensus_key_change = pos::ConsensusKeyChange::try_from_slice(
            &tx.data()
                .ok_or_else(|| Error::Other("Invalid Data".to_string()))?,
        )
        .map_err(|err| {
            Error::from(EncodingError::Conversion(err.to_string()))
        })?;

        tv.name = "Change_Consensus_Key_0".to_string();

        tv.output.extend(vec![
            format!("Type : Change consensus key"),
            format!(
                "New consensus key : {}",
                consensus_key_change.consensus_key
            ),
            format!("Validator : {}", consensus_key_change.validator),
        ]);

        tv.output_expert.extend(vec![
            format!(
                "New consensus key : {}",
                consensus_key_change.consensus_key
            ),
            format!("Validator : {}", consensus_key_change.validator),
        ]);
    } else if code_sec.tag == Some(TX_UNJAIL_VALIDATOR_WASM.to_string()) {
        let address = Address::try_from_slice(
            &tx.data()
                .ok_or_else(|| Error::Other("Invalid Data".to_string()))?,
        )
        .map_err(|err| {
            Error::from(EncodingError::Conversion(err.to_string()))
        })?;

        tv.name = "Unjail_Validator_0".to_string();

        tv.output.extend(vec![
            format!("Type : Unjail Validator"),
            format!("Validator : {}", address),
        ]);

        tv.output_expert.push(format!("Validator : {}", address));
    } else if code_sec.tag == Some(TX_DEACTIVATE_VALIDATOR_WASM.to_string()) {
        let address = Address::try_from_slice(
            &tx.data()
                .ok_or_else(|| Error::Other("Invalid Data".to_string()))?,
        )
        .map_err(|err| {
            Error::from(EncodingError::Conversion(err.to_string()))
        })?;

        tv.name = "Deactivate_Validator_0".to_string();

        tv.output.extend(vec![
            format!("Type : Deactivate Validator"),
            format!("Validator : {}", address),
        ]);

        tv.output_expert.push(format!("Validator : {}", address));
    } else if code_sec.tag == Some(TX_REACTIVATE_VALIDATOR_WASM.to_string()) {
        let address = Address::try_from_slice(
            &tx.data()
                .ok_or_else(|| Error::Other("Invalid Data".to_string()))?,
        )
        .map_err(|err| {
            Error::from(EncodingError::Conversion(err.to_string()))
        })?;

        tv.name = "Reactivate_Validator_0".to_string();

        tv.output.extend(vec![
            format!("Type : Reactivate Validator"),
            format!("Validator : {}", address),
        ]);

        tv.output_expert.push(format!("Validator : {}", address));
    } else if code_sec.tag == Some(TX_REDELEGATE_WASM.to_string()) {
        let redelegation = pos::Redelegation::try_from_slice(
            &tx.data()
                .ok_or_else(|| Error::Other("Invalid Data".to_string()))?,
        )
        .map_err(|err| {
            Error::from(EncodingError::Conversion(err.to_string()))
        })?;

        tv.name = "Redelegate_0".to_string();

        tv.output.extend(vec![
            format!("Type : Redelegate"),
            format!("Source Validator : {}", redelegation.src_validator),
            format!("Destination Validator : {}", redelegation.dest_validator),
            format!("Owner : {}", redelegation.owner),
            format!(
                "Amount : {}",
                to_ledger_decimal(&redelegation.amount.to_string_native())
            ),
        ]);

        tv.output_expert.extend(vec![
            format!("Source Validator : {}", redelegation.src_validator),
            format!("Destination Validator : {}", redelegation.dest_validator),
            format!("Owner : {}", redelegation.owner),
            format!(
                "Amount : {}",
                to_ledger_decimal(&redelegation.amount.to_string_native())
            ),
        ]);
    } else if code_sec.tag == Some(TX_UPDATE_STEWARD_COMMISSION.to_string()) {
        let update = UpdateStewardCommission::try_from_slice(
            &tx.data()
                .ok_or_else(|| Error::Other("Invalid Data".to_string()))?,
        )
        .map_err(|err| {
            Error::from(EncodingError::Conversion(err.to_string()))
        })?;

        tv.name = "Update_Steward_Commission_0".to_string();
        tv.output.extend(vec![
            format!("Type : Update Steward Commission"),
            format!("Steward : {}", update.steward),
        ]);
        for (address, dec) in &update.commission {
            tv.output.push(format!("Commission : {} {}", address, dec));
        }

        tv.output_expert
            .push(format!("Steward : {}", update.steward));
        for (address, dec) in &update.commission {
            tv.output_expert
                .push(format!("Commission : {} {}", address, dec));
        }
    } else if code_sec.tag == Some(TX_RESIGN_STEWARD.to_string()) {
        let address = Address::try_from_slice(
            &tx.data()
                .ok_or_else(|| Error::Other("Invalid Data".to_string()))?,
        )
        .map_err(|err| {
            Error::from(EncodingError::Conversion(err.to_string()))
        })?;

        tv.name = "Resign_Steward_0".to_string();

        tv.output.extend(vec![
            format!("Type : Resign Steward"),
            format!("Steward : {}", address),
        ]);

        tv.output_expert.push(format!("Steward : {}", address));
    } else if code_sec.tag == Some(TX_BRIDGE_POOL_WASM.to_string()) {
        let transfer = PendingTransfer::try_from_slice(
            &tx.data()
                .ok_or_else(|| Error::Other("Invalid Data".to_string()))?,
        )
        .map_err(|err| {
            Error::from(EncodingError::Conversion(err.to_string()))
        })?;

        tv.name = "Bridge_Pool_Transfer_0".to_string();

        tv.output.extend(vec![
            format!("Type : Bridge Pool Transfer"),
            format!("Transfer Kind : {}", transfer.transfer.kind),
            format!("Transfer Sender : {}", transfer.transfer.sender),
            format!("Transfer Recipient : {}", transfer.transfer.recipient),
            format!("Transfer Asset : {}", transfer.transfer.asset),
            format!("Transfer Amount : {}", transfer.transfer.amount),
            format!("Gas Payer : {}", transfer.gas_fee.payer),
            format!("Gas Token : {}", transfer.gas_fee.token),
            format!("Gas Amount : {}", transfer.gas_fee.amount),
        ]);

        tv.output_expert.extend(vec![
            format!("Transfer Kind : {}", transfer.transfer.kind),
            format!("Transfer Sender : {}", transfer.transfer.sender),
            format!("Transfer Recipient : {}", transfer.transfer.recipient),
            format!("Transfer Asset : {}", transfer.transfer.asset),
            format!("Transfer Amount : {}", transfer.transfer.amount),
            format!("Gas Payer : {}", transfer.gas_fee.payer),
            format!("Gas Token : {}", transfer.gas_fee.token),
            format!("Gas Amount : {}", transfer.gas_fee.amount),
        ]);
    } else {
        tv.name = "Custom_0".to_string();
        tv.output.push("Type : Custom".to_string());
    }

    if let Some(wrapper) = tx.header.wrapper() {
        let fee_amount_per_gas_unit =
            to_ledger_decimal(&wrapper.fee.amount_per_gas_unit.to_string());
        tv.output_expert.extend(vec![
            format!("Timestamp : {}", tx.header.timestamp.0),
            format!("Pubkey : {}", wrapper.pk),
            format!("Epoch : {}", wrapper.epoch),
            format!("Gas limit : {}", u64::from(wrapper.gas_limit)),
        ]);
        if let Some(token) = tokens.get(&wrapper.fee.token) {
            tv.output_expert.push(format!(
                "Fees/gas unit : {} {}",
                token.to_uppercase(),
                fee_amount_per_gas_unit,
            ));
        } else {
            tv.output_expert.extend(vec![
                format!("Fee token : {}", wrapper.fee.token),
                format!("Fees/gas unit : {}", fee_amount_per_gas_unit),
            ]);
        }
    }

    // Finally, index each line and break those that are too long
    format_outputs(&mut tv.output);
    format_outputs(&mut tv.output_expert);
    Ok(tv)
}
