//! Functions to sign transactions

#![allow(clippy::result_large_err)]

use std::collections::BTreeMap;
use std::fmt::Display;

use borsh::BorshDeserialize;
use borsh_ext::BorshSerializeExt;
use data_encoding::HEXLOWER;
use itertools::Itertools;
use masp_primitives::asset_type::AssetType;
use masp_primitives::transaction::components::sapling::fees::{
    InputView, OutputView,
};
use namada_account::{AccountPublicKeysMap, InitAccount, UpdateAccount};
use namada_core::address::{Address, ImplicitAddress, InternalAddress, MASP};
use namada_core::arith::checked;
use namada_core::collections::{HashMap, HashSet};
use namada_core::key::*;
use namada_core::masp::{
    AssetData, ExtendedViewingKey, MaspTxId, PaymentAddress,
};
use namada_core::token::{Amount, DenominatedAmount};
use namada_governance::storage::proposal::{
    InitProposalData, ProposalType, VoteProposalData,
};
use namada_governance::storage::vote::ProposalVote;
use namada_ibc::{MsgNftTransfer, MsgTransfer};
use namada_io::*;
use namada_parameters::storage as parameter_storage;
use namada_token as token;
use namada_token::storage_key::balance_key;
use namada_tx::data::pgf::UpdateStewardCommission;
use namada_tx::data::pos::BecomeValidator;
use namada_tx::data::{pos, Fee};
use namada_tx::{MaspBuilder, Section, SignatureIndex, Tx};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use crate::args::SdkTypes;
use crate::error::{EncodingError, Error, TxSubmitError};
use crate::eth_bridge_pool::PendingTransfer;
use crate::governance::storage::proposal::{AddRemove, PGFAction, PGFTarget};
use crate::rpc::validate_amount;
use crate::token::Account;
use crate::tx::{
    Commitment, TX_BECOME_VALIDATOR_WASM, TX_BOND_WASM, TX_BRIDGE_POOL_WASM,
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
use crate::{args, rpc, Namada};

/// A structure holding the signing data to craft a transaction
#[derive(Clone, PartialEq)]
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
    /// ID of the Transaction needing signing
    pub shielded_hash: Option<MaspTxId>,
}

/// Find the public key for the given address and try to load the keypair
/// for it from the wallet.
///
/// If the keypair is encrypted but a password is not
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
///
/// If the keypair is encrypted but a password is not supplied, then it is
/// interactively prompted. Errors if the key cannot be found or loaded.
pub fn find_key_by_pk<U: WalletIo>(
    wallet: &mut Wallet<U>,
    args: &args::Tx,
    public_key: &common::PublicKey,
) -> Result<common::SecretKey, Error> {
    wallet
        .find_key_by_pk(public_key, args.password.clone())
        .map_err(|err| {
            Error::Other(format!(
                "Unable to load the keypair from the wallet for public key \
                 {}. Failed with: {}",
                public_key, err
            ))
        })
}

/// Given CLI arguments and some defaults, determine the rightful transaction
/// signer.
///
/// Return the given signing key or public key of the given signer if
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
        // No signature needed if the source is MASP
        Some(MASP) => Ok(vec![]),
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
    /// Fee header
    FeeHeader,
    /// Raw header
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
                let sigidx =
                    serde_json::from_slice::<SignatureIndex>(bytes).unwrap();
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
        let mut signing_tx_keypairs = vec![];

        for public_key in &signing_data.public_keys {
            if !used_pubkeys.contains(public_key) {
                let Ok(secret_key) =
                    find_key_by_pk(&mut wallet, args, public_key)
                else {
                    // If the secret key is not found, continue because the
                    // hardware wallet may still be able to sign this
                    continue;
                };
                used_pubkeys.insert(public_key.clone());
                signing_tx_keypairs.push(secret_key);
            }
        }

        if !signing_tx_keypairs.is_empty() {
            tx.sign_raw(
                signing_tx_keypairs,
                account_public_keys_map,
                signing_data.owner,
            );
        }
    }

    // Then try to sign the raw header using the hardware wallet
    for pubkey in &signing_data.public_keys {
        if !used_pubkeys.contains(pubkey) && *pubkey != signing_data.fee_payer {
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

    // Then try signing the wrapper header (fee payer) with the software wallet
    // otherwise use the fallback
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
        // The case where tge fee payer also signs the inner transaction
        Err(_)
            if signing_data.public_keys.contains(&signing_data.fee_payer) =>
        {
            *tx = sign(
                tx.clone(),
                signing_data.fee_payer.clone(),
                HashSet::from([Signable::FeeHeader, Signable::RawHeader]),
                user_data,
            )
            .await?;
            used_pubkeys.insert(signing_data.fee_payer.clone());
        }
        // The case where the fee payer does not sign the inner transaction
        Err(_) => {
            *tx = sign(
                tx.clone(),
                signing_data.fee_payer.clone(),
                HashSet::from([Signable::FeeHeader]),
                user_data,
            )
            .await?;
        }
    }
    // Then make sure that the number of public keys used exceeds the threshold
    let used_pubkeys_len = used_pubkeys
        .len()
        .try_into()
        .expect("Public keys associated with account exceed 127");
    if used_pubkeys_len < signing_data.threshold {
        Err(Error::from(TxSubmitError::MissingSigningKeys(
            signing_data.threshold,
            used_pubkeys_len,
        )))
    } else {
        Ok(())
    }
}

/// Return the necessary data regarding an account to be able to generate a
/// signature section
pub async fn aux_signing_data(
    context: &impl Namada,
    args: &args::Tx<SdkTypes>,
    owner: Option<Address>,
    default_signer: Option<Address>,
    extra_public_keys: Vec<common::PublicKey>,
    disposable_signing_key: bool,
) -> Result<SigningTxData, Error> {
    let mut public_keys =
        tx_signers(context, args, default_signer.clone()).await?;
    public_keys.extend(extra_public_keys.clone());

    let (account_public_keys_map, threshold) = match &owner {
        Some(owner @ Address::Established(_)) => {
            let account =
                rpc::get_account_info(context.client(), owner).await?;
            if let Some(account) = account {
                (Some(account.clone().public_keys_map), account.threshold)
            } else {
                return Err(Error::from(TxSubmitError::InvalidAccount(
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
                return Err(Error::from(TxSubmitError::InvalidAccount(
                    owner.encode(),
                )));
            }
        },
        None => (
            Some(AccountPublicKeysMap::from_iter(public_keys.clone())),
            0u8,
        ),
    };

    let fee_payer = if disposable_signing_key {
        context
            .wallet_mut()
            .await
            .gen_disposable_signing_key(&mut OsRng)
            .to_public()
    } else {
        match &args.wrapper_fee_payer {
            Some(keypair) => keypair.clone(),
            None => public_keys
                .first()
                .ok_or(TxSubmitError::InvalidFeePayer)?
                .clone(),
        }
    };

    Ok(SigningTxData {
        owner,
        public_keys,
        threshold,
        account_public_keys_map,
        fee_payer,
        shielded_hash: None,
    })
}

/// Information about the post-fee balance of the tx's source. Used to correctly
/// handle balance validation in the inner tx
pub struct TxSourcePostBalance {
    /// The balance of the tx source after the tx has been applied
    pub post_balance: Amount,
    /// The source address of the tx
    pub source: Address,
    /// The token of the tx
    pub token: Address,
}

/// Validate the fee amount and token
pub async fn validate_fee<N: Namada>(
    context: &N,
    args: &args::Tx<SdkTypes>,
) -> Result<DenominatedAmount, Error> {
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

    Ok(fee_amount)
}

/// Validate the fee of the transaction in case of a transparent fee payer,
/// computing the updated post balance
pub async fn validate_transparent_fee<N: Namada>(
    context: &N,
    args: &args::Tx<SdkTypes>,
    fee_payer: &common::PublicKey,
) -> Result<(DenominatedAmount, TxSourcePostBalance), Error> {
    let fee_amount = validate_fee(context, args).await?;
    let fee_payer_address = Address::from(fee_payer);

    let balance_key = balance_key(&args.fee_token, &fee_payer_address);
    #[allow(clippy::disallowed_methods)]
    let balance = rpc::query_storage_value::<_, token::Amount>(
        context.client(),
        &balance_key,
    )
    .await
    .unwrap_or_default();

    let total_fee = checked!(fee_amount.amount() * u64::from(args.gas_limit))?;
    let mut updated_balance = TxSourcePostBalance {
        post_balance: balance,
        source: fee_payer_address.clone(),
        token: args.fee_token.clone(),
    };

    match total_fee.checked_sub(balance) {
        Some(diff) if !diff.is_zero() => {
            let token_addr = args.fee_token.clone();
            if !args.force {
                let fee_amount =
                    context.format_amount(&token_addr, total_fee).await;

                let balance = context.format_amount(&token_addr, balance).await;
                return Err(Error::from(TxSubmitError::BalanceTooLowForFees(
                    fee_payer_address,
                    token_addr,
                    fee_amount,
                    balance,
                )));
            }

            updated_balance.post_balance = Amount::zero();
        }
        _ => {
            updated_balance.post_balance =
                checked!(updated_balance.post_balance - total_fee)?;
        }
    };

    Ok((fee_amount, updated_balance))
}

/// Create a wrapper tx from a normal tx. Get the hash of the
/// wrapper and its payload which is needed for monitoring its
/// progress on chain.
pub async fn wrap_tx(
    tx: &mut Tx,
    args: &args::Tx<SdkTypes>,
    fee_amount: DenominatedAmount,
    fee_payer: common::PublicKey,
) -> Result<(), Error> {
    tx.add_wrapper(
        Fee {
            amount_per_gas_unit: fee_amount,
            token: args.fee_token.clone(),
        },
        fee_payer,
        // TODO(namada#1625): partially validate the gas limit in client
        args.gas_limit,
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
    /// String blob
    pub blob: String,
    /// Index integer
    pub index: u64,
    /// Name
    pub name: String,
    /// Regular output
    pub output: Vec<String>,
    /// Expert-mode output
    pub output_expert: Vec<String>,
    /// Is valid?
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
    assets: &HashMap<AssetType, AssetData>,
    prefix: &str,
) {
    if let Some(decoded) = assets.get(token) {
        // If the AssetType can be decoded, then at least display Addressees
        if let Some(token) = tokens.get(&decoded.token) {
            output.push(format!(
                "{}Amount : {} {}",
                prefix,
                token.to_uppercase(),
                DenominatedAmount::new(
                    token::Amount::from_masp_denominated(
                        amount,
                        decoded.position
                    ),
                    decoded.denom,
                ),
            ));
        } else {
            output.extend(vec![
                format!("{}Token : {}", prefix, decoded.token),
                format!(
                    "{}Amount : {}",
                    prefix,
                    DenominatedAmount::new(
                        token::Amount::from_masp_denominated(
                            amount,
                            decoded.position
                        ),
                        decoded.denom,
                    ),
                ),
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

/// Convert a map with key pairs into a nested structure
fn nest_map<V>(
    map: BTreeMap<Account, V>,
) -> BTreeMap<Address, BTreeMap<Address, V>> {
    let mut nested = BTreeMap::new();
    for (account, v) in map {
        let inner: &mut BTreeMap<_, _> =
            nested.entry(account.owner).or_default();
        inner.insert(account.token, v);
    }
    nested
}

/// Adds a Ledger output for the senders and destinations for transparent and
/// MASP transactions
async fn make_ledger_token_transfer_endpoints(
    tokens: &HashMap<Address, String>,
    output: &mut Vec<String>,
    transfer: &token::Transfer,
    builder: Option<&MaspBuilder>,
    assets: &HashMap<AssetType, AssetData>,
) -> Result<(), Error> {
    for (owner, changes) in nest_map(transfer.sources.clone()) {
        // MASP inputs will be printed below
        if owner != MASP {
            output.push(format!("Sender : {}", owner));
            for (token, amount) in changes {
                make_ledger_amount_addr(
                    tokens, output, amount, &token, "Sending ",
                );
            }
        }
    }
    if let Some(builder) = builder {
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
    for (owner, changes) in nest_map(transfer.targets.clone()) {
        // MASP outputs will be printed below
        if owner != MASP {
            output.push(format!("Destination : {}", owner));
            for (token, amount) in changes {
                make_ledger_amount_addr(
                    tokens,
                    output,
                    amount,
                    &token,
                    "Receiving ",
                );
            }
        }
    }
    if let Some(builder) = builder {
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

    Ok(())
}

/// Convert decimal numbers into the format used by Ledger. Specifically remove
/// all insignificant zeros occurring after decimal point.
fn to_ledger_decimal(amount: &str) -> String {
    if amount.contains('.') {
        let mut amount = amount.trim_end_matches('0').to_string();
        if amount.ends_with('.') {
            amount.pop();
        }
        amount
    } else {
        amount.to_string()
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

fn proposal_type_to_ledger_vector(
    proposal_type: &ProposalType,
    tx: &Tx,
    output: &mut Vec<String>,
) {
    match proposal_type {
        ProposalType::Default => {
            output.push("Proposal type : Default".to_string())
        }
        ProposalType::DefaultWithWasm(hash) => {
            output.push("Proposal type : Default".to_string());
            let extra = tx
                .get_section(hash)
                .and_then(|x| Section::extra_data_sec(x.as_ref()))
                .expect("unable to load vp code")
                .code
                .hash();
            output
                .push(format!("Proposal hash : {}", HEXLOWER.encode(&extra.0)));
        }
        ProposalType::PGFSteward(actions) => {
            output.push("Proposal type : PGF Steward".to_string());
            let mut actions = actions.iter().collect::<Vec<_>>();
            // Print the test vectors in the same order as the serializations
            actions.sort();
            for action in actions {
                match action {
                    AddRemove::Add(addr) => {
                        output.push(format!("Add : {}", addr))
                    }
                    AddRemove::Remove(addr) => {
                        output.push(format!("Remove : {}", addr))
                    }
                }
            }
        }
        ProposalType::PGFPayment(actions) => {
            output.push("Proposal type : PGF Payment".to_string());
            for action in actions {
                match action {
                    PGFAction::Continuous(AddRemove::Add(
                        PGFTarget::Internal(target),
                    )) => {
                        output.push(
                            "PGF Action : Add Continuous Payment".to_string(),
                        );
                        output.push(format!("Target: {}", target.target));
                        output.push(format!(
                            "Amount: NAM {}",
                            to_ledger_decimal(
                                &target.amount.to_string_native()
                            )
                        ));
                    }
                    PGFAction::Continuous(AddRemove::Add(PGFTarget::Ibc(
                        target,
                    ))) => {
                        output.push(
                            "PGF Action : Add Continuous Payment".to_string(),
                        );
                        output.push(format!("Target: {}", target.target));
                        output.push(format!(
                            "Amount: NAM {}",
                            to_ledger_decimal(
                                &target.amount.to_string_native()
                            )
                        ));
                        output.push(format!("Port ID: {}", target.port_id));
                        output
                            .push(format!("Channel ID: {}", target.channel_id));
                    }
                    PGFAction::Continuous(AddRemove::Remove(
                        PGFTarget::Internal(target),
                    )) => {
                        output.push(
                            "PGF Action : Remove Continuous Payment"
                                .to_string(),
                        );
                        output.push(format!("Target: {}", target.target));
                        output.push(format!(
                            "Amount: NAM {}",
                            to_ledger_decimal(
                                &target.amount.to_string_native()
                            )
                        ));
                    }
                    PGFAction::Continuous(AddRemove::Remove(
                        PGFTarget::Ibc(target),
                    )) => {
                        output.push(
                            "PGF Action : Remove Continuous Payment"
                                .to_string(),
                        );
                        output.push(format!("Target: {}", target.target));
                        output.push(format!(
                            "Amount: NAM {}",
                            to_ledger_decimal(
                                &target.amount.to_string_native()
                            )
                        ));
                        output.push(format!("Port ID: {}", target.port_id));
                        output
                            .push(format!("Channel ID: {}", target.channel_id));
                    }
                    PGFAction::Retro(PGFTarget::Internal(target)) => {
                        output.push("PGF Action : Retro Payment".to_string());
                        output.push(format!("Target: {}", target.target));
                        output.push(format!(
                            "Amount: NAM {}",
                            to_ledger_decimal(
                                &target.amount.to_string_native()
                            )
                        ));
                    }
                    PGFAction::Retro(PGFTarget::Ibc(target)) => {
                        output.push("PGF Action : Retro Payment".to_string());
                        output.push(format!("Target: {}", target.target));
                        output.push(format!(
                            "Amount: NAM {}",
                            to_ledger_decimal(
                                &target.amount.to_string_native()
                            )
                        ));
                        output.push(format!("Port ID: {}", target.port_id));
                        output
                            .push(format!("Channel ID: {}", target.channel_id));
                    }
                }
            }
        }
    }
}

// Find the MASP Builder that was used to construct the given Transaction.
// Additionally record how to decode AssetTypes using information from the
// builder.
fn find_masp_builder<'a>(
    tx: &'a Tx,
    shielded_section_hash: Option<MaspTxId>,
    asset_types: &mut HashMap<AssetType, AssetData>,
) -> Result<Option<&'a MaspBuilder>, std::io::Error> {
    for section in &tx.sections {
        match section {
            Section::MaspBuilder(builder)
                if Some(builder.target) == shielded_section_hash =>
            {
                for decoded in &builder.asset_types {
                    asset_types.insert(decoded.encode()?, decoded.clone());
                }
                return Ok(Some(builder));
            }
            _ => {}
        }
    }
    Ok(None)
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

    for cmt in tx.commitments() {
        // FIXME: need to push some string to differentiate between the
        // different txs of the bundle?
        let code_sec = tx
            .get_section(cmt.code_sechash())
            .ok_or_else(|| {
                Error::Other(
                    "expected tx code section to be present".to_string(),
                )
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
                &tx.data(cmt)
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
                &tx.data(cmt)
                    .ok_or_else(|| Error::Other("Invalid Data".to_string()))?,
            )
            .map_err(|err| {
                Error::from(EncodingError::Conversion(err.to_string()))
            })?;

            tv.name = "Become_Validator_0".to_string();

            tv.output
                .extend(vec!["Type : Become Validator".to_string()]);
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
            if let Some(name) = &init_validator.name {
                tv.output.push(format!("Name : {}", name));
            }
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
            if let Some(avatar) = &init_validator.avatar {
                tv.output.push(format!("Avatar : {}", avatar));
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
            if let Some(name) = &init_validator.name {
                tv.output_expert.push(format!("Name : {}", name));
            }
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
            if let Some(avatar) = &init_validator.avatar {
                tv.output_expert.push(format!("Avatar : {}", avatar));
            }
        } else if code_sec.tag == Some(TX_INIT_PROPOSAL.to_string()) {
            let init_proposal_data = InitProposalData::try_from_slice(
                &tx.data(cmt)
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
            proposal_type_to_ledger_vector(
                &init_proposal_data.r#type,
                tx,
                &mut tv.output,
            );
            tv.output.extend(vec![
                format!("Author : {}", init_proposal_data.author),
                format!(
                    "Voting start epoch : {}",
                    init_proposal_data.voting_start_epoch
                ),
                format!(
                    "Voting end epoch : {}",
                    init_proposal_data.voting_end_epoch
                ),
                format!(
                    "Activation epoch : {}",
                    init_proposal_data.activation_epoch
                ),
                format!("Content : {}", HEXLOWER.encode(&extra.0)),
            ]);

            proposal_type_to_ledger_vector(
                &init_proposal_data.r#type,
                tx,
                &mut tv.output_expert,
            );
            tv.output_expert.extend(vec![
                format!("Author : {}", init_proposal_data.author),
                format!(
                    "Voting start epoch : {}",
                    init_proposal_data.voting_start_epoch
                ),
                format!(
                    "Voting end epoch : {}",
                    init_proposal_data.voting_end_epoch
                ),
                format!(
                    "Activation epoch : {}",
                    init_proposal_data.activation_epoch
                ),
                format!("Content : {}", HEXLOWER.encode(&extra.0)),
            ]);
        } else if code_sec.tag == Some(TX_VOTE_PROPOSAL.to_string()) {
            let vote_proposal = VoteProposalData::try_from_slice(
                &tx.data(cmt)
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

            tv.output_expert.extend(vec![
                format!("ID : {}", vote_proposal.id),
                format!("Vote : {}", LedgerProposalVote(&vote_proposal.vote)),
                format!("Voter : {}", vote_proposal.voter),
            ]);
        } else if code_sec.tag == Some(TX_REVEAL_PK.to_string()) {
            let public_key = common::PublicKey::try_from_slice(
                &tx.data(cmt)
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
                &tx.data(cmt)
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
                    let vp_code = if extra.tag == Some(VP_USER_WASM.to_string())
                    {
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
            let transfer = token::Transfer::try_from_slice(
                &tx.data(cmt)
                    .ok_or_else(|| Error::Other("Invalid Data".to_string()))?,
            )
            .map_err(|err| {
                Error::from(EncodingError::Conversion(err.to_string()))
            })?;
            tv.name = "Transfer_0".to_string();
            tv.output.push("Type : Transfer".to_string());

            // To facilitate lookups of MASP AssetTypes
            let mut asset_types = HashMap::new();
            let builder = find_masp_builder(
                tx,
                transfer.shielded_section_hash,
                &mut asset_types,
            )
            .map_err(|_| Error::Other("Invalid Data".to_string()))?;
            make_ledger_token_transfer_endpoints(
                &tokens,
                &mut tv.output,
                &transfer,
                builder,
                &asset_types,
            )
            .await?;
            make_ledger_token_transfer_endpoints(
                &tokens,
                &mut tv.output_expert,
                &transfer,
                builder,
                &asset_types,
            )
            .await?;
        } else if code_sec.tag == Some(TX_IBC_WASM.to_string()) {
            let data = tx
                .data(cmt)
                .ok_or_else(|| Error::Other("Invalid Data".to_string()))?;

            if let Ok(transfer) =
                MsgTransfer::<token::Transfer>::try_from_slice(data.as_ref())
            {
                tv.name = "IBC_Transfer_0".to_string();
                tv.output.push("Type : IBC Transfer".to_string());
                let transfer_token = format!(
                    "{} {}",
                    transfer.message.packet_data.token.amount,
                    transfer.message.packet_data.token.denom
                );
                tv.output.extend(vec![
                    format!("Source port : {}", transfer.message.port_id_on_a),
                    format!(
                        "Source channel : {}",
                        transfer.message.chan_id_on_a
                    ),
                    format!("Token : {}", transfer_token),
                    format!("Sender : {}", transfer.message.packet_data.sender),
                    format!(
                        "Receiver : {}",
                        transfer.message.packet_data.receiver
                    ),
                    format!(
                        "Timeout height : {}",
                        transfer.message.timeout_height_on_b
                    ),
                    format!(
                        "Timeout timestamp : {}",
                        transfer.message.timeout_timestamp_on_b,
                    ),
                ]);
                tv.output_expert.extend(vec![
                    format!("Source port : {}", transfer.message.port_id_on_a),
                    format!(
                        "Source channel : {}",
                        transfer.message.chan_id_on_a
                    ),
                    format!("Token : {}", transfer_token),
                    format!("Sender : {}", transfer.message.packet_data.sender),
                    format!(
                        "Receiver : {}",
                        transfer.message.packet_data.receiver
                    ),
                ]);
                if !transfer.message.packet_data.memo.to_string().is_empty() {
                    tv.output_expert.push(format!(
                        "Memo : {}",
                        transfer.message.packet_data.memo
                    ));
                }
                tv.output_expert.extend(vec![
                    format!(
                        "Timeout height : {}",
                        transfer.message.timeout_height_on_b
                    ),
                    format!(
                        "Timeout timestamp : {}",
                        transfer.message.timeout_timestamp_on_b,
                    ),
                ]);
                if let Some(transfer) = transfer.transfer {
                    // To facilitate lookups of MASP AssetTypes
                    let mut asset_types = HashMap::new();
                    let builder = find_masp_builder(
                        tx,
                        transfer.shielded_section_hash,
                        &mut asset_types,
                    )
                    .map_err(|_| Error::Other("Invalid Data".to_string()))?;
                    make_ledger_token_transfer_endpoints(
                        &tokens,
                        &mut tv.output,
                        &transfer,
                        builder,
                        &asset_types,
                    )
                    .await?;
                    make_ledger_token_transfer_endpoints(
                        &tokens,
                        &mut tv.output_expert,
                        &transfer,
                        builder,
                        &asset_types,
                    )
                    .await?;
                }
            } else if let Ok(transfer) =
                MsgNftTransfer::<token::Transfer>::try_from_slice(data.as_ref())
            {
                tv.name = "IBC_NFT_Transfer_0".to_string();
                tv.output.push("Type : IBC NFT Transfer".to_string());
                tv.output.extend(vec![
                    format!("Source port : {}", transfer.message.port_id_on_a),
                    format!(
                        "Source channel : {}",
                        transfer.message.chan_id_on_a
                    ),
                    format!(
                        "Class ID: {}",
                        transfer.message.packet_data.class_id
                    ),
                ]);
                if let Some(class_uri) = &transfer.message.packet_data.class_uri
                {
                    tv.output.push(format!("Class URI: {}", class_uri));
                }
                if let Some(class_data) =
                    &transfer.message.packet_data.class_data
                {
                    tv.output.push(format!("Class data: {}", class_data));
                }
                for (idx, token_id) in
                    transfer.message.packet_data.token_ids.0.iter().enumerate()
                {
                    tv.output.push(format!("Token ID: {}", token_id));
                    if let Some(token_uris) =
                        &transfer.message.packet_data.token_uris
                    {
                        tv.output.push(format!(
                            "Token URI: {}",
                            token_uris.get(idx).ok_or_else(|| Error::Other(
                                "Invalid Data".to_string()
                            ))?,
                        ));
                    }
                    if let Some(token_data) =
                        &transfer.message.packet_data.token_data
                    {
                        tv.output.push(format!(
                            "Token data: {}",
                            token_data.get(idx).ok_or_else(|| Error::Other(
                                "Invalid Data".to_string()
                            ))?,
                        ));
                    }
                }
                tv.output.extend(vec![
                    format!("Sender : {}", transfer.message.packet_data.sender),
                    format!(
                        "Receiver : {}",
                        transfer.message.packet_data.receiver
                    ),
                ]);
                tv.output.extend(vec![
                    format!(
                        "Timeout height : {}",
                        transfer.message.timeout_height_on_b
                    ),
                    format!(
                        "Timeout timestamp : {}",
                        transfer.message.timeout_timestamp_on_b,
                    ),
                ]);
                tv.output_expert.extend(vec![
                    format!("Source port : {}", transfer.message.port_id_on_a),
                    format!(
                        "Source channel : {}",
                        transfer.message.chan_id_on_a
                    ),
                    format!(
                        "Class ID: {}",
                        transfer.message.packet_data.class_id
                    ),
                ]);
                if let Some(class_uri) = &transfer.message.packet_data.class_uri
                {
                    tv.output_expert.push(format!("Class URI: {}", class_uri));
                }
                if let Some(class_data) =
                    &transfer.message.packet_data.class_data
                {
                    tv.output_expert
                        .push(format!("Class data: {}", class_data));
                }
                for (idx, token_id) in
                    transfer.message.packet_data.token_ids.0.iter().enumerate()
                {
                    tv.output_expert.push(format!("Token ID: {}", token_id));
                    if let Some(token_uris) =
                        &transfer.message.packet_data.token_uris
                    {
                        tv.output_expert.push(format!(
                            "Token URI: {}",
                            token_uris.get(idx).ok_or_else(|| Error::Other(
                                "Invalid Data".to_string()
                            ))?,
                        ));
                    }
                    if let Some(token_data) =
                        &transfer.message.packet_data.token_data
                    {
                        tv.output_expert.push(format!(
                            "Token data: {}",
                            token_data.get(idx).ok_or_else(|| Error::Other(
                                "Invalid Data".to_string()
                            ))?,
                        ));
                    }
                }
                tv.output_expert.extend(vec![
                    format!("Sender : {}", transfer.message.packet_data.sender),
                    format!(
                        "Receiver : {}",
                        transfer.message.packet_data.receiver
                    ),
                ]);
                if let Some(memo) = &transfer.message.packet_data.memo {
                    if !memo.to_string().is_empty() {
                        tv.output_expert.push(format!("Memo: {}", memo));
                    }
                }
                tv.output_expert.extend(vec![
                    format!(
                        "Timeout height : {}",
                        transfer.message.timeout_height_on_b
                    ),
                    format!(
                        "Timeout timestamp : {}",
                        transfer.message.timeout_timestamp_on_b,
                    ),
                ]);
                if let Some(transfer) = transfer.transfer {
                    // To facilitate lookups of MASP AssetTypes
                    let mut asset_types = HashMap::new();
                    let builder = find_masp_builder(
                        tx,
                        transfer.shielded_section_hash,
                        &mut asset_types,
                    )
                    .map_err(|_| Error::Other("Invalid Data".to_string()))?;
                    make_ledger_token_transfer_endpoints(
                        &tokens,
                        &mut tv.output,
                        &transfer,
                        builder,
                        &asset_types,
                    )
                    .await?;
                    make_ledger_token_transfer_endpoints(
                        &tokens,
                        &mut tv.output_expert,
                        &transfer,
                        builder,
                        &asset_types,
                    )
                    .await?;
                }
            } else {
                return Result::Err(Error::Other("Invalid Data".to_string()));
            }
        } else if code_sec.tag == Some(TX_BOND_WASM.to_string()) {
            let bond = pos::Bond::try_from_slice(
                &tx.data(cmt)
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
                &tx.data(cmt)
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
                &tx.data(cmt)
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
                &tx.data(cmt)
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
                &tx.data(cmt)
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
                &tx.data(cmt)
                    .ok_or_else(|| Error::Other("Invalid Data".to_string()))?,
            )
            .map_err(|err| {
                Error::from(EncodingError::Conversion(err.to_string()))
            })?;

            tv.name = "Change_MetaData_0".to_string();

            tv.output.extend(vec!["Type : Change metadata".to_string()]);

            let mut other_items = vec![];
            other_items
                .push(format!("Validator : {}", metadata_change.validator));
            if let Some(name) = metadata_change.name {
                other_items.push(format!("Name : {}", name));
            }
            if let Some(email) = metadata_change.email {
                other_items.push(format!("Email : {}", email));
            }
            if let Some(description) = metadata_change.description {
                other_items.push(format!("Description : {}", description));
            }
            if let Some(website) = metadata_change.website {
                other_items.push(format!("Website : {}", website));
            }
            if let Some(discord_handle) = metadata_change.discord_handle {
                other_items
                    .push(format!("Discord handle : {}", discord_handle));
            }
            if let Some(avatar) = metadata_change.avatar {
                other_items.push(format!("Avatar : {}", avatar));
            }
            if let Some(commission_rate) = metadata_change.commission_rate {
                other_items
                    .push(format!("Commission rate : {}", commission_rate));
            }

            tv.output.extend(other_items.clone());
            tv.output_expert.extend(other_items);
        } else if code_sec.tag == Some(TX_CHANGE_CONSENSUS_KEY_WASM.to_string())
        {
            let consensus_key_change = pos::ConsensusKeyChange::try_from_slice(
                &tx.data(cmt)
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
                &tx.data(cmt)
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
        } else if code_sec.tag == Some(TX_DEACTIVATE_VALIDATOR_WASM.to_string())
        {
            let address = Address::try_from_slice(
                &tx.data(cmt)
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
        } else if code_sec.tag == Some(TX_REACTIVATE_VALIDATOR_WASM.to_string())
        {
            let address = Address::try_from_slice(
                &tx.data(cmt)
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
                &tx.data(cmt)
                    .ok_or_else(|| Error::Other("Invalid Data".to_string()))?,
            )
            .map_err(|err| {
                Error::from(EncodingError::Conversion(err.to_string()))
            })?;

            tv.name = "Redelegate_0".to_string();

            tv.output.extend(vec![
                format!("Type : Redelegate"),
                format!("Source Validator : {}", redelegation.src_validator),
                format!(
                    "Destination Validator : {}",
                    redelegation.dest_validator
                ),
                format!("Owner : {}", redelegation.owner),
                format!(
                    "Amount : {}",
                    to_ledger_decimal(&redelegation.amount.to_string_native())
                ),
            ]);

            tv.output_expert.extend(vec![
                format!("Source Validator : {}", redelegation.src_validator),
                format!(
                    "Destination Validator : {}",
                    redelegation.dest_validator
                ),
                format!("Owner : {}", redelegation.owner),
                format!(
                    "Amount : {}",
                    to_ledger_decimal(&redelegation.amount.to_string_native())
                ),
            ]);
        } else if code_sec.tag == Some(TX_UPDATE_STEWARD_COMMISSION.to_string())
        {
            let update = UpdateStewardCommission::try_from_slice(
                &tx.data(cmt)
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
            for (address, dec) in update.commission.iter() {
                tv.output.push(format!("Validator : {}", address));
                tv.output.push(format!("Commission Rate : {}", dec));
            }

            tv.output_expert
                .push(format!("Steward : {}", update.steward));
            for (address, dec) in update.commission.iter() {
                tv.output_expert.push(format!("Validator : {}", address));
                tv.output_expert.push(format!("Commission Rate : {}", dec));
            }
        } else if code_sec.tag == Some(TX_RESIGN_STEWARD.to_string()) {
            let address = Address::try_from_slice(
                &tx.data(cmt)
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
                &tx.data(cmt)
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

        if cmt.memo_sechash() != &namada_core::hash::Hash::default() {
            match tx
                .get_section(cmt.memo_sechash())
                .unwrap()
                .extra_data_sec()
                .unwrap()
                .code
            {
                Commitment::Hash(hash) => {
                    tv.output.push(format!(
                        "Memo Hash : {}",
                        HEXLOWER.encode(&hash.0)
                    ));
                    tv.output_expert.push(format!(
                        "Memo Hash : {}",
                        HEXLOWER.encode(&hash.0)
                    ));
                }
                Commitment::Id(id) => {
                    let memo = String::from_utf8(id).map_err(|err| {
                        Error::from(EncodingError::Conversion(err.to_string()))
                    })?;
                    tv.output.push(format!("Memo : {}", memo));
                    tv.output_expert.push(format!("Memo : {}", memo));
                }
            }
        }

        if let Some(wrapper) = tx.header.wrapper() {
            let fee_amount_per_gas_unit =
                to_ledger_decimal(&wrapper.fee.amount_per_gas_unit.to_string());
            tv.output_expert.extend(vec![
                format!("Timestamp : {}", tx.header.timestamp.0),
                format!("Pubkey : {}", wrapper.pk),
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
    }

    // Finally, index each line and break those that are too long
    format_outputs(&mut tv.output);
    format_outputs(&mut tv.output_expert);
    Ok(tv)
}
