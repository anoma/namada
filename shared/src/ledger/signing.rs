//! Functions to sign transactions
use std::collections::HashMap;
use std::fmt::Display;
use std::io::ErrorKind;

use borsh::{BorshDeserialize, BorshSerialize};
use data_encoding::HEXLOWER;
use itertools::Itertools;
use masp_primitives::asset_type::AssetType;
use masp_primitives::transaction::components::sapling::fees::{
    InputView, OutputView,
};
use namada_core::proto::SignatureIndex;
use namada_core::types::account::AccountPublicKeysMap;
use namada_core::types::address::{
    masp, masp_tx_key, Address, ImplicitAddress,
};
// use namada_core::types::storage::Key;
use namada_core::types::token::{self, Amount, DenominatedAmount, MaspDenom};
use namada_core::types::transaction::pos;
use prost::Message;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::core::ledger::governance::storage::proposal::ProposalType;
use crate::core::ledger::governance::storage::vote::{
    StorageProposalVote, VoteType,
};
use crate::ibc::applications::transfer::msgs::transfer::MsgTransfer;
use crate::ibc_proto::google::protobuf::Any;
use crate::ledger::masp::make_asset_type;
use crate::ledger::parameters::storage as parameter_storage;
use crate::ledger::rpc::{format_denominated_amount, query_wasm_code_hash};
use crate::ledger::tx::{
    Error, TX_BOND_WASM, TX_CHANGE_COMMISSION_WASM, TX_IBC_WASM,
    TX_INIT_ACCOUNT_WASM, TX_INIT_PROPOSAL, TX_INIT_VALIDATOR_WASM,
    TX_REVEAL_PK, TX_TRANSFER_WASM, TX_UNBOND_WASM, TX_UNJAIL_VALIDATOR_WASM,
    TX_UPDATE_ACCOUNT_WASM, TX_VOTE_PROPOSAL, TX_WITHDRAW_WASM, VP_USER_WASM,
};
pub use crate::ledger::wallet::store::AddressVpType;
use crate::ledger::wallet::{Wallet, WalletUtils};
use crate::ledger::{args, rpc};
use crate::proto::{MaspBuilder, Section, Tx};
use crate::types::key::*;
use crate::types::masp::{ExtendedViewingKey, PaymentAddress};
use crate::types::storage::Epoch;
use crate::types::token::Transfer;
use crate::types::transaction::account::{InitAccount, UpdateAccount};
use crate::types::transaction::governance::{
    InitProposalData, VoteProposalData,
};
use crate::types::transaction::pos::InitValidator;
use crate::types::transaction::{Fee, TxType};

#[cfg(feature = "std")]
/// Env. var specifying where to store signing test vectors
const ENV_VAR_LEDGER_LOG_PATH: &str = "NAMADA_LEDGER_LOG_PATH";
#[cfg(feature = "std")]
/// Env. var specifying where to store transaction debug outputs
const ENV_VAR_TX_LOG_PATH: &str = "NAMADA_TX_LOG_PATH";

/// A struture holding the signing data to craft a transaction
#[derive(Clone)]
pub struct SigningTxData {
    /// The public keys associated to an account
    pub public_keys: Vec<common::PublicKey>,
    /// The threshold associated to an account
    pub threshold: u8,
    /// The public keys to index map associated to an account
    pub account_public_keys_map: Option<AccountPublicKeysMap>,
    /// The public keys of the fee payer
    pub gas_payer: common::PublicKey,
}

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
            rpc::get_public_key_at(client, addr, 0)
                .await
                .ok_or(Error::Other(format!(
                    "No public key found for the address {}",
                    addr.encode()
                )))
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
    public_key: &common::PublicKey,
) -> Result<common::SecretKey, Error> {
    if *public_key == masp_tx_key().ref_to() {
        // We already know the secret key corresponding to the MASP sentinal key
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
pub async fn tx_signers<
    C: crate::ledger::queries::Client + Sync,
    U: WalletUtils,
>(
    client: &C,
    wallet: &mut Wallet<U>,
    args: &args::Tx,
    default: Option<Address>,
) -> Result<Vec<common::PublicKey>, Error> {
    let signer = if !&args.signing_keys.is_empty() {
        let public_keys =
            args.signing_keys.iter().map(|key| key.ref_to()).collect();
        return Ok(public_keys);
    } else if let Some(verification_key) = &args.verification_key {
        return Ok(vec![verification_key.clone()]);
    } else {
        // Otherwise use the signer determined by the caller
        default
    };

    // Now actually fetch the signing key and apply it
    match signer {
        Some(signer) if signer == masp() => Ok(vec![masp_tx_key().ref_to()]),
        Some(signer) => Ok(vec![
            find_pk::<C, U>(client, wallet, &signer, args.password.clone())
                .await?,
        ]),
        None => other_err(
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
pub fn sign_tx<U: WalletUtils>(
    wallet: &mut Wallet<U>,
    args: &args::Tx,
    tx: &mut Tx,
    signing_data: SigningTxData,
) {
    if !args.signatures.is_empty() {
        let signatures = args
            .signatures
            .iter()
            .map(|bytes| SignatureIndex::deserialize(bytes).unwrap())
            .collect();
        tx.add_signatures(signatures);
    } else if let Some(account_public_keys_map) =
        signing_data.account_public_keys_map
    {
        let signing_tx_keypairs = signing_data
            .public_keys
            .iter()
            .filter_map(|public_key| {
                match find_key_by_pk(wallet, args, public_key) {
                    Ok(secret_key) => Some(secret_key),
                    Err(_) => None,
                }
            })
            .collect::<Vec<common::SecretKey>>();
        tx.sign_raw(signing_tx_keypairs, account_public_keys_map);
    }

    let fee_payer_keypair =
        find_key_by_pk(wallet, args, &signing_data.gas_payer).expect("");
    tx.sign_wrapper(fee_payer_keypair);
}

/// Return the necessary data regarding an account to be able to generate a
/// multisignature section
pub async fn aux_signing_data<
    C: crate::ledger::queries::Client + Sync,
    U: WalletUtils,
>(
    client: &C,
    wallet: &mut Wallet<U>,
    args: &args::Tx,
    owner: &Option<Address>,
    default_signer: Option<Address>,
) -> Result<SigningTxData, Error> {
    let public_keys = if owner.is_some() || args.gas_payer.is_none() {
        tx_signers::<C, U>(client, wallet, args, default_signer.clone()).await?
    } else {
        vec![]
    };

    let (account_public_keys_map, threshold) = match owner {
        Some(owner @ Address::Established(_)) => {
            let account = rpc::get_account_info::<C>(client, owner).await;
            if let Some(account) = account {
                (Some(account.public_keys_map), account.threshold)
            } else {
                return Err(Error::InvalidAccount(owner.encode()));
            }
        }
        Some(Address::Implicit(_)) => (
            Some(AccountPublicKeysMap::from_iter(public_keys.clone())),
            1u8,
        ),
        Some(owner @ Address::Internal(_)) => {
            return Err(Error::InvalidAccount(owner.encode()));
        }
        None => (None, 0u8),
    };

    let gas_payer = match &args.gas_payer {
        Some(keypair) => keypair.ref_to(),
        None => public_keys.get(0).ok_or(Error::InvalidFeePayer)?.clone(),
    };

    Ok(SigningTxData {
        public_keys,
        threshold,
        account_public_keys_map,
        gas_payer,
    })
}

#[cfg(not(feature = "mainnet"))]
/// Solve the PoW challenge if balance is insufficient to pay transaction fees
/// or if solution is explicitly requested.
pub async fn solve_pow_challenge<C: crate::ledger::queries::Client + Sync>(
    client: &C,
    args: &args::Tx,
    keypair: &common::PublicKey,
    requires_pow: bool,
) -> (Option<crate::core::ledger::testnet_pow::Solution>, Fee) {
    let wrapper_tx_fees_key = parameter_storage::get_wrapper_tx_fees_key();
    let gas_amount = rpc::query_storage_value::<C, token::Amount>(
        client,
        &wrapper_tx_fees_key,
    )
    .await
    .unwrap_or_default();
    let gas_token = &args.gas_token;
    let source = Address::from(keypair);
    let balance_key = token::balance_key(gas_token, &source);
    let balance =
        rpc::query_storage_value::<C, token::Amount>(client, &balance_key)
            .await
            .unwrap_or_default();
    let is_bal_sufficient = gas_amount <= balance;
    if !is_bal_sufficient {
        let token_addr = args.gas_token.clone();
        let err_msg = format!(
            "The wrapper transaction source doesn't have enough balance to \
             pay fee {}, got {}.",
            format_denominated_amount(client, &token_addr, gas_amount).await,
            format_denominated_amount(client, &token_addr, balance).await,
        );
        if !args.force && cfg!(feature = "mainnet") {
            panic!("{}", err_msg);
        }
    }
    let fee = Fee {
        amount: gas_amount,
        token: gas_token.clone(),
    };
    // A PoW solution can be used to allow zero-fee testnet transactions
    // If the address derived from the keypair doesn't have enough balance
    // to pay for the fee, allow to find a PoW solution instead.
    if (requires_pow || !is_bal_sufficient) && !args.dump_tx {
        println!("The transaction requires the completion of a PoW challenge.");
        // Obtain a PoW challenge for faucet withdrawal
        let challenge = rpc::get_testnet_pow_challenge(client, source).await;

        // Solve the solution, this blocks until a solution is found
        let solution = challenge.solve();
        (Some(solution), fee)
    } else {
        (None, fee)
    }
}

#[cfg(not(feature = "mainnet"))]
/// Update the PoW challenge inside the given transaction
pub async fn update_pow_challenge<C: crate::ledger::queries::Client + Sync>(
    client: &C,
    args: &args::Tx,
    tx: &mut Tx,
    keypair: &common::PublicKey,
    requires_pow: bool,
) {
    if let TxType::Wrapper(wrapper) = &mut tx.header.tx_type {
        let (pow_solution, fee) =
            solve_pow_challenge(client, args, keypair, requires_pow).await;
        wrapper.fee = fee;
        wrapper.pow_solution = pow_solution;
    }
}

/// Create a wrapper tx from a normal tx. Get the hash of the
/// wrapper and its payload which is needed for monitoring its
/// progress on chain.
pub async fn wrap_tx<C: crate::ledger::queries::Client + Sync>(
    client: &C,
    tx: &mut Tx,
    args: &args::Tx,
    epoch: Epoch,
    gas_payer: common::PublicKey,
    #[cfg(not(feature = "mainnet"))] requires_pow: bool,
) {
    #[cfg(not(feature = "mainnet"))]
    let (pow_solution, fee) =
        solve_pow_challenge(client, args, &gas_payer, requires_pow).await;

    tx.add_wrapper(
        fee,
        gas_payer,
        epoch,
        args.gas_limit.clone(),
        #[cfg(not(feature = "mainnet"))]
        pow_solution,
    );
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
            output.push(format!(
                "{}Amount : {} {}",
                prefix,
                token.to_uppercase(),
                to_ledger_decimal(&formatted_amt),
            ));
        } else {
            output.extend(vec![
                format!("{}Token : {}", prefix, token),
                format!(
                    "{}Amount : {}",
                    prefix,
                    to_ledger_decimal(&formatted_amt)
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

/// Internal method used to generate transaction test vectors
#[cfg(feature = "std")]
pub async fn generate_test_vector<
    C: crate::ledger::queries::Client + Sync,
    U: WalletUtils,
>(
    client: &C,
    wallet: &mut Wallet<U>,
    tx: &Tx,
) {
    use std::env;
    use std::fs::File;
    use std::io::Write;

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
}

/// Convert decimal numbers into the format used by Ledger. Specifically remove
/// all insignificant zeros occuring after decimal point.
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
struct LedgerProposalVote<'a>(&'a StorageProposalVote);

impl<'a> Display for LedgerProposalVote<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.0 {
            StorageProposalVote::Yay(vote_type) => match vote_type {
                VoteType::Default => write!(f, "yay"),
                VoteType::PGFSteward => write!(f, "yay for PGF steward"),
                VoteType::PGFPayment => {
                    write!(f, "yay for PGF payment proposal")
                }
            },

            StorageProposalVote::Nay => write!(f, "nay"),
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
    let update_account_hash =
        query_wasm_code_hash(client, TX_UPDATE_ACCOUNT_WASM)
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
    let unjail_validator_hash =
        query_wasm_code_hash(client, TX_UNJAIL_VALIDATOR_WASM)
            .await
            .unwrap();

    // To facilitate lookups of human-readable token names
    let tokens: HashMap<Address, String> = wallet
        .get_addresses()
        .into_iter()
        .map(|(alias, addr)| (addr, alias))
        .collect();

    let mut tv = LedgerVector {
        blob: HEXLOWER
            .encode(&tx.try_to_vec().expect("unable to serialize transaction")),
        index: 0,
        valid: true,
        name: "Custom_0".to_string(),
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

        tv.name = "Init_Account_0".to_string();

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
        tv.output.extend(vec![format!("Type : Init Account")]);
        tv.output.extend(
            init_account
                .public_keys
                .iter()
                .map(|k| format!("Public key : {}", k.to_string())),
        );
        tv.output.extend(vec![
            format!("Threshold : {}", init_account.threshold),
            format!("VP type : {}", vp_code),
        ]);

        tv.output_expert.extend(
            init_account
                .public_keys
                .iter()
                .map(|k| format!("Public key : {}", k.to_string())),
        );
        tv.output_expert.extend(vec![
            format!("Threshold : {}", init_account.threshold),
            format!("VP type : {}", HEXLOWER.encode(&extra.0)),
        ]);
    } else if code_hash == init_validator_hash {
        let init_validator =
            InitValidator::try_from_slice(&tx.data().ok_or_else(|| {
                std::io::Error::from(ErrorKind::InvalidData)
            })?)?;

        tv.name = "Init_Validator_0".to_string();

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

        tv.output.extend(vec!["Type : Init Validator".to_string()]);
        tv.output.extend(
            init_validator
                .account_keys
                .iter()
                .map(|k| format!("Account key : {}", k.to_string())),
        );
        tv.output.extend(vec![
            format!("Threshold : {}", init_validator.threshold),
            format!("Consensus key : {}", init_validator.consensus_key),
            format!("Ethereum cold key : {}", init_validator.eth_cold_key),
            format!("Ethereum hot key : {}", init_validator.eth_hot_key),
            format!("Protocol key : {}", init_validator.protocol_key),
            format!("DKG key : {}", init_validator.dkg_key),
            format!("Commission rate : {}", init_validator.commission_rate),
            format!(
                "Maximum commission rate change : {}",
                init_validator.max_commission_rate_change
            ),
            format!("Validator VP type : {}", vp_code,),
        ]);

        tv.output_expert.extend(
            init_validator
                .account_keys
                .iter()
                .map(|k| format!("Account key : {}", k.to_string())),
        );
        tv.output_expert.extend(vec![
            format!("Threshold : {}", init_validator.threshold),
            format!("Consensus key : {}", init_validator.consensus_key),
            format!("Ethereum cold key : {}", init_validator.eth_cold_key),
            format!("Ethereum hot key : {}", init_validator.eth_hot_key),
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

        tv.name = "Init_Proposal_0".to_string();

        let extra = tx
            .get_section(&init_proposal_data.content)
            .and_then(|x| Section::extra_data_sec(x.as_ref()))
            .expect("unable to load vp code")
            .code
            .hash();

        tv.output.push(format!("Type : Init proposal"));
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
    } else if code_hash == vote_proposal_hash {
        let vote_proposal =
            VoteProposalData::try_from_slice(&tx.data().ok_or_else(|| {
                std::io::Error::from(ErrorKind::InvalidData)
            })?)?;

        tv.name = "Vote_Proposal_0".to_string();

        tv.output.extend(vec![
            format!("Type : Vote Proposal"),
            format!("ID : {}", vote_proposal.id),
            format!("Vote : {}", LedgerProposalVote(&vote_proposal.vote)),
            format!("Voter : {}", vote_proposal.voter),
        ]);
        for delegation in &vote_proposal.delegations {
            tv.output.push(format!("Delegations : {}", delegation));
        }

        tv.output_expert.extend(vec![
            format!("ID : {}", vote_proposal.id),
            format!("Vote : {}", LedgerProposalVote(&vote_proposal.vote)),
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

        tv.name = "Reveal_Pubkey_0".to_string();

        tv.output.extend(vec![
            format!("Type : Reveal Pubkey"),
            format!("Public key : {}", public_key),
        ]);

        tv.output_expert
            .extend(vec![format!("Public key : {}", public_key)]);
    } else if code_hash == update_account_hash {
        let transfer =
            UpdateAccount::try_from_slice(&tx.data().ok_or_else(|| {
                std::io::Error::from(ErrorKind::InvalidData)
            })?)?;

        tv.name = "Update_VP_0".to_string();

        match &transfer.vp_code_hash {
            Some(hash) => {
                let extra = tx
                    .get_section(hash)
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
            }
            None => (),
        };
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

        tv.name = "Transfer_0".to_string();

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
        let any_msg = Any::decode(
            tx.data()
                .ok_or_else(|| std::io::Error::from(ErrorKind::InvalidData))?
                .as_ref(),
        )
        .map_err(|x| std::io::Error::new(ErrorKind::Other, x))?;

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
                        transfer.timeout_timestamp_on_b
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
                        transfer.timeout_timestamp_on_b
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
    } else if code_hash == bond_hash {
        let bond =
            pos::Bond::try_from_slice(&tx.data().ok_or_else(|| {
                std::io::Error::from(ErrorKind::InvalidData)
            })?)?;

        tv.name = "Bond_0".to_string();

        tv.output.push(format!("Type : Bond"));
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
    } else if code_hash == unbond_hash {
        let unbond =
            pos::Unbond::try_from_slice(&tx.data().ok_or_else(|| {
                std::io::Error::from(ErrorKind::InvalidData)
            })?)?;

        tv.name = "Unbond_0".to_string();

        tv.output.push(format!("Type : Unbond"));
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
    } else if code_hash == withdraw_hash {
        let withdraw =
            pos::Withdraw::try_from_slice(&tx.data().ok_or_else(|| {
                std::io::Error::from(ErrorKind::InvalidData)
            })?)?;

        tv.name = "Withdraw_0".to_string();

        tv.output.push(format!("Type : Withdraw"));
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
    } else if code_hash == change_commission_hash {
        let commission_change = pos::CommissionChange::try_from_slice(
            &tx.data()
                .ok_or_else(|| std::io::Error::from(ErrorKind::InvalidData))?,
        )?;

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
    } else if code_hash == unjail_validator_hash {
        let address =
            Address::try_from_slice(&tx.data().ok_or_else(|| {
                std::io::Error::from(ErrorKind::InvalidData)
            })?)?;

        tv.name = "Unjail_Validator_0".to_string();

        tv.output.extend(vec![
            format!("Type : Unjail Validator"),
            format!("Validator : {}", address),
        ]);

        tv.output_expert.push(format!("Validator : {}", address));
    } else {
        tv.name = "Custom_0".to_string();
        tv.output.push("Type : Custom".to_string());
    }

    if let Some(wrapper) = tx.header.wrapper() {
        let gas_token = wrapper.fee.token.clone();
        let gas_limit = format_denominated_amount(
            client,
            &gas_token,
            Amount::from(wrapper.gas_limit),
        )
        .await;
        let gas_amount =
            format_denominated_amount(client, &gas_token, wrapper.fee.amount)
                .await;
        tv.output_expert.extend(vec![
            format!("Timestamp : {}", tx.header.timestamp.0),
            format!("Pubkey : {}", wrapper.pk),
            format!("Epoch : {}", wrapper.epoch),
            format!("Gas limit : {}", gas_limit),
        ]);
        if let Some(token) = tokens.get(&wrapper.fee.token) {
            tv.output_expert.push(format!(
                "Fees : {} {}",
                token.to_uppercase(),
                to_ledger_decimal(&gas_amount)
            ));
        } else {
            tv.output_expert.extend(vec![
                format!("Fee token : {}", gas_token),
                format!("Fee amount : {}", gas_amount),
            ]);
        }
    }

    // Finally, index each line and break those that are too long
    format_outputs(&mut tv.output);
    format_outputs(&mut tv.output_expert);
    Ok(tv)
}
