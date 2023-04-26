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
use namada::ibc::core::ics26_routing::msgs::Ics26Envelope;
use namada::ledger::parameters::storage as parameter_storage;
use namada::proof_of_stake::Epoch;
use namada::proto::{Section, Signature, Tx};
use namada::types::address::{
    apfel, btc, dot, eth, kartoffel, masp, nam, schnitzel, Address,
    ImplicitAddress,
};
use namada::types::ibc::data::IbcMessage;
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
use crate::client::tendermint_rpc_types::TxBroadcastData;
use crate::client::tx::{
    make_asset_type, TX_BOND_WASM, TX_CHANGE_COMMISSION_WASM, TX_IBC_WASM,
    TX_INIT_ACCOUNT_WASM, TX_INIT_PROPOSAL, TX_INIT_VALIDATOR_WASM,
    TX_REVEAL_PK, TX_TRANSFER_WASM, TX_UNBOND_WASM, TX_UPDATE_VP_WASM,
    TX_VOTE_PROPOSAL, TX_WITHDRAW_WASM, VP_USER_WASM,
};
use crate::facade::tendermint_config::net::Address as TendermintAddress;
use crate::facade::tendermint_rpc::HttpClient;
use crate::wallet::Wallet;

/// Env. var specifying where to store signing test vectors
const ENV_VAR_LEDGER_LOG_PATH: &str = "NAMADA_LEDGER_LOG_PATH";
/// Env. var specifying where to store transaction debug outputs
const ENV_VAR_TX_LOG_PATH: &str = "NAMADA_TX_LOG_PATH";

/// Find the public key for the given address and try to load the keypair
/// for it from the wallet. Panics if the key cannot be found or loaded.
pub async fn find_keypair(
    wallet: &mut Wallet,
    addr: &Address,
    ledger_address: TendermintAddress,
) -> common::SecretKey {
    match addr {
        Address::Established(_) => {
            println!(
                "Looking-up public key of {} from the ledger...",
                addr.encode()
            );
            let public_key = rpc::get_public_key(addr, ledger_address)
                .await
                .unwrap_or_else(|| {
                    eprintln!(
                        "No public key found for the address {}",
                        addr.encode()
                    );
                    cli::safe_exit(1);
                });
            wallet.find_key_by_pk(&public_key).unwrap_or_else(|err| {
                eprintln!(
                    "Unable to load the keypair from the wallet for public \
                     key {}. Failed with: {}",
                    public_key, err
                );
                cli::safe_exit(1)
            })
        }
        Address::Implicit(ImplicitAddress(pkh)) => {
            wallet.find_key_by_pkh(pkh).unwrap_or_else(|err| {
                eprintln!(
                    "Unable to load the keypair from the wallet for the \
                     implicit address {}. Failed with: {}",
                    addr.encode(),
                    err
                );
                cli::safe_exit(1)
            })
        }
        Address::Internal(_) => {
            eprintln!(
                "Internal address {} doesn't have any signing keys.",
                addr
            );
            cli::safe_exit(1)
        }
    }
}

/// Carries types that can be directly/indirectly used to sign a transaction.
#[allow(clippy::large_enum_variant)]
#[derive(Clone)]
pub enum TxSigningKey {
    // Do not sign any transaction
    None,
    // Obtain the actual keypair from wallet and use that to sign
    WalletKeypair(WalletKeypair),
    // Obtain the keypair corresponding to given address from wallet and sign
    WalletAddress(WalletAddress),
    // Directly use the given secret key to sign transactions
    SecretKey(common::SecretKey),
}

/// Given CLI arguments and some defaults, determine the rightful transaction
/// signer. Return the given signing key or public key of the given signer if
/// possible. If no explicit signer given, use the `default`. If no `default`
/// is given, panics.
pub async fn tx_signer(
    ctx: &mut Context,
    args: &args::Tx,
    mut default: TxSigningKey,
) -> common::SecretKey {
    // Override the default signing key source if possible
    if let Some(signing_key) = &args.signing_key {
        default = TxSigningKey::WalletKeypair(signing_key.clone());
    } else if let Some(signer) = &args.signer {
        default = TxSigningKey::WalletAddress(signer.clone());
    }
    // Now actually fetch the signing key and apply it
    match default {
        TxSigningKey::WalletKeypair(signing_key) => {
            ctx.get_cached(&signing_key)
        }
        TxSigningKey::WalletAddress(signer) => {
            let signer = ctx.get(&signer);
            let signing_key = find_keypair(
                &mut ctx.wallet,
                &signer,
                args.ledger_address.clone(),
            )
            .await;
            // Check if the signer is implicit account that needs to reveal its
            // PK first
            if matches!(signer, Address::Implicit(_)) {
                let pk: common::PublicKey = signing_key.ref_to();
                super::tx::reveal_pk_if_needed(ctx, &pk, args).await;
            }
            signing_key
        }
        TxSigningKey::SecretKey(signing_key) => signing_key,
        TxSigningKey::None => {
            panic!(
                "All transactions must be signed; please either specify the \
                 key or the address from which to look up the signing key."
            );
        }
    }
}

/// Sign a transaction with a given signing key or public key of a given signer.
/// If no explicit signer given, use the `default`. If no `default` is given,
/// panics.
///
/// If this is not a dry run, the tx is put in a wrapper and returned along with
/// hashes needed for monitoring the tx on chain.
///
/// If it is a dry run, it is not put in a wrapper, but returned as is.
pub async fn sign_tx(
    mut ctx: Context,
    mut tx: Tx,
    args: &args::Tx,
    default: TxSigningKey,
    #[cfg(not(feature = "mainnet"))] requires_pow: bool,
) -> (Context, TxBroadcastData) {
    if args.dump_tx {
        dump_tx_helper(&ctx, &tx, "unsigned", None);
    }

    let keypair = tx_signer(&mut ctx, args, default).await;
    // Sign over the transacttion data
    tx.add_section(Section::Signature(Signature::new(
        tx.data_sechash(),
        &keypair,
    )));
    // Sign over the transaction code
    tx.add_section(Section::Signature(Signature::new(
        tx.code_sechash(),
        &keypair,
    )));

    if args.dump_tx {
        dump_tx_helper(&ctx, &tx, "signed", None);
    }

    let epoch = match args.epoch {
        Some(epoch) if args.unchecked => epoch,
        _ => {
            rpc::query_and_print_epoch(args::Query {
                ledger_address: args.ledger_address.clone(),
            })
            .await
        }
    };
    let broadcast_data = if args.dry_run {
        tx.update_header(TxType::Decrypted(DecryptedTx::Decrypted {
            #[cfg(not(feature = "mainnet"))]
            // To be able to dry-run testnet faucet withdrawal, pretend 
            // that we got a valid PoW
            has_valid_pow: true,
        }));
        TxBroadcastData::DryRun(tx)
    } else {
        sign_wrapper(
            &ctx,
            args,
            epoch,
            tx,
            &keypair,
            #[cfg(not(feature = "mainnet"))]
            requires_pow,
        )
        .await
    };

    if args.dump_tx && !args.dry_run {
        let (wrapper_tx, wrapper_hash) = match broadcast_data {
            TxBroadcastData::DryRun(_) => panic!(
                "somehow created a dry run transaction without --dry-run"
            ),
            TxBroadcastData::Wrapper {
                ref tx,
                ref wrapper_hash,
                decrypted_hash: _,
            } => (tx, wrapper_hash),
        };

        dump_tx_helper(&ctx, wrapper_tx, "wrapper", Some(wrapper_hash));
    }

    (ctx, broadcast_data)
}

pub fn dump_tx_helper(
    ctx: &Context,
    tx: &Tx,
    extension: &str,
    precomputed_hash: Option<&String>,
) {
    let chain_dir = ctx.config.ledger.chain_dir();
    let hash = match precomputed_hash {
        Some(hash) => hash.to_owned(),
        None => format!("{}", tx.header_hash()),
    };
    let filename = chain_dir.join(hash).with_extension(extension);
    let tx_bytes = tx.to_bytes();

    std::fs::write(filename, tx_bytes)
        .expect("expected to be able to write tx dump file");
}

/// Create a wrapper tx from a normal tx. Get the hash of the
/// wrapper and its payload which is needed for monitoring its
/// progress on chain.
pub async fn sign_wrapper(
    ctx: &Context,
    args: &args::Tx,
    epoch: Epoch,
    mut tx: Tx,
    keypair: &common::SecretKey,
    #[cfg(not(feature = "mainnet"))] requires_pow: bool,
) -> TxBroadcastData {
    let client = HttpClient::new(args.ledger_address.clone()).unwrap();

    let fee_amount = if cfg!(feature = "mainnet") {
        Amount::whole(MIN_FEE)
    } else if args.unchecked {
        args.fee_amount
    } else {
        let wrapper_tx_fees_key = parameter_storage::get_wrapper_tx_fees_key();
        rpc::query_storage_value::<token::Amount>(&client, &wrapper_tx_fees_key)
            .await
            .unwrap_or_default()
    };
    let fee_token = ctx.get(&args.fee_token);
    let source = Address::from(&keypair.ref_to());
    let balance_key = token::balance_key(&fee_token, &source);
    let mut is_bal_sufficient = true;
    if !args.unchecked {
        let balance =
            rpc::query_storage_value::<token::Amount>(&client, &balance_key)
                .await
                .unwrap_or_default();
        is_bal_sufficient = fee_amount <= balance;
        if !is_bal_sufficient {
            eprintln!(
                "The wrapper transaction source doesn't have enough balance \
                 to pay fee {fee_amount}, got {balance}."
            );
            if !args.force && cfg!(feature = "mainnet") {
                cli::safe_exit(1);
            }
        }
    }

    #[cfg(not(feature = "mainnet"))]
    // A PoW solution can be used to allow zero-fee testnet transactions
    let pow_solution: Option<namada::core::ledger::testnet_pow::Solution> = {
        // If the address derived from the keypair doesn't have enough balance
        // to pay for the fee, allow to find a PoW solution instead.
        if requires_pow || !is_bal_sufficient {
            println!(
                "The transaction requires the completion of a PoW challenge."
            );
            // Obtain a PoW challenge for faucet withdrawal
            let challenge = rpc::get_testnet_pow_challenge(
                source,
                args.ledger_address.clone(),
            )
            .await;

            // Solve the solution, this blocks until a solution is found
            let solution = challenge.solve();
            Some(solution)
        } else {
            None
        }
    };

    // This object governs how the payload will be processed
    tx.update_header(TxType::Wrapper(WrapperTx::new(
        Fee {
            amount: fee_amount,
            token: fee_token,
        },
        keypair,
        epoch,
        args.gas_limit.clone(),
        #[cfg(not(feature = "mainnet"))]
        pow_solution,
    )));
    tx.header.chain_id = ctx.config.ledger.chain_id.clone();
    tx.header.expiration = args.expiration;
    // Then sign over the bound wrapper
    tx.add_section(Section::Signature(Signature::new(
        &tx.header_hash(),
        keypair,
    )));

    // Attempt to decode the construction
    if let Ok(path) = env::var(ENV_VAR_LEDGER_LOG_PATH) {
        let mut tx = tx.clone();
        // Contract the large data blobs in the transaction
        tx.wallet_filter();
        // Convert the transaction to Ledger format
        let decoding =
            to_ledger_vector(ctx, &tx).expect("unable to decode transaction");
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

    // Remove all the sensitive sections
    tx.protocol_filter();
    // Encrypt all sections not relating to the header
    tx.encrypt(&Default::default());
    // We use this to determine when the wrapper tx makes it on-chain
    let wrapper_hash = tx.header_hash().to_string();
    // We use this to determine when the decrypted inner tx makes it
    // on-chain
    let decrypted_hash = tx
        .clone()
        .update_header(TxType::Raw)
        .header_hash()
        .to_string();
    TxBroadcastData::Wrapper {
        tx,
        wrapper_hash,
        decrypted_hash,
    }
}

/// Represents the transaction data that is displayed on a Ledger device
#[derive(Default, Serialize, Deserialize)]
struct LedgerVector {
    blob: String,
    index: u64,
    name: String,
    output: Vec<String>,
    output_expert: Vec<String>,
    valid: bool,
}

/// The tokens that will be hardcoded into the wallet
fn tokens() -> HashMap<Address, &'static str> {
    vec![
        (nam(), "NAM"),
        (btc(), "BTC"),
        (eth(), "ETH"),
        (dot(), "DOT"),
        (schnitzel(), "Schnitzel"),
        (apfel(), "Apfel"),
        (kartoffel(), "Kartoffel"),
    ]
    .into_iter()
    .collect()
}

/// Adds a Ledger output line describing a given transaction amount and address
fn make_ledger_amount_addr(
    output: &mut Vec<String>,
    amount: Amount,
    token: &Address,
    prefix: &str,
) {
    // To facilitate lookups of human-readable token names
    let tokens = tokens();

    if let Some(token) = tokens.get(token) {
        output.push(format!("{}Amount: {} {}", prefix, token, amount));
    } else {
        output.extend(vec![
            format!("{}Token: {}", prefix, token),
            format!("{}Amount: {}", prefix, amount),
        ]);
    }
}

/// Adds a Ledger output line describing a given transaction amount and asset
/// type
fn make_ledger_amount_asset(
    output: &mut Vec<String>,
    amount: u64,
    token: &AssetType,
    assets: &HashMap<AssetType, (Address, Epoch)>,
    prefix: &str,
) {
    // To facilitate lookups of human-readable token names
    let tokens = tokens();

    if let Some((token, _epoch)) = assets.get(token) {
        // If the AssetType can be decoded, then at least display Addressees
        if let Some(token) = tokens.get(token) {
            output.push(format!(
                "{}Amount: {} {}",
                prefix,
                token,
                Amount::from(amount)
            ));
        } else {
            output.extend(vec![
                format!("{}Token: {}", prefix, token),
                format!("{}Amount: {}", prefix, Amount::from(amount)),
            ]);
        }
    } else {
        // Otherwise display the raw AssetTypes
        output.extend(vec![
            format!("{}Token: {}", prefix, token),
            format!("{}Amount: {}", prefix, Amount::from(amount)),
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

/// Converts the given transaction to the form that is displayed on the Ledger
/// device
fn to_ledger_vector(
    ctx: &Context,
    tx: &Tx,
) -> Result<LedgerVector, std::io::Error> {
    let init_account_hash = hash_tx(&ctx.read_wasm(TX_INIT_ACCOUNT_WASM));
    let init_validator_hash = hash_tx(&ctx.read_wasm(TX_INIT_VALIDATOR_WASM));
    let init_proposal_hash = hash_tx(&ctx.read_wasm(TX_INIT_PROPOSAL));
    let vote_proposal_hash = hash_tx(&ctx.read_wasm(TX_VOTE_PROPOSAL));
    let reveal_pk_hash = hash_tx(&ctx.read_wasm(TX_REVEAL_PK));
    let update_vp_hash = hash_tx(&ctx.read_wasm(TX_UPDATE_VP_WASM));
    let transfer_hash = hash_tx(&ctx.read_wasm(TX_TRANSFER_WASM));
    let ibc_hash = hash_tx(&ctx.read_wasm(TX_IBC_WASM));
    let bond_hash = hash_tx(&ctx.read_wasm(TX_BOND_WASM));
    let unbond_hash = hash_tx(&ctx.read_wasm(TX_UNBOND_WASM));
    let withdraw_hash = hash_tx(&ctx.read_wasm(TX_WITHDRAW_WASM));
    let change_commission_hash =
        hash_tx(&ctx.read_wasm(TX_CHANGE_COMMISSION_WASM));
    let user_hash = hash_tx(&ctx.read_wasm(VP_USER_WASM));

    // To facilitate lookups of human-readable token names
    let tokens = tokens();

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
        let init_account = InitAccount::try_from_slice(
            &tx.data()
                .ok_or_else(|| Error::from(ErrorKind::InvalidData))?,
        )?;

        tv.name = "Init Account 0".to_string();

        let extra = tx
            .get_section(&init_account.vp_code_hash)
            .and_then(Section::extra_data_sec)
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
        let init_validator = InitValidator::try_from_slice(
            &tx.data()
                .ok_or_else(|| Error::from(ErrorKind::InvalidData))?,
        )?;

        tv.name = "Init Validator 0".to_string();

        let extra = tx
            .get_section(&init_validator.validator_vp_code_hash)
            .and_then(Section::extra_data_sec)
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
        let init_proposal_data = InitProposalData::try_from_slice(
            &tx.data()
                .ok_or_else(|| Error::from(ErrorKind::InvalidData))?,
        )?;

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
        let content: BTreeMap<String, String> =
            BorshDeserialize::try_from_slice(&init_proposal_data.content)?;
        if !content.is_empty() {
            for (key, value) in &content {
                tv.output.push(format!("Content {} : {}", key, value));
            }
        } else {
            tv.output.push("Content : (none)".to_string());
        }

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
        if !content.is_empty() {
            for (key, value) in content {
                tv.output_expert
                    .push(format!("Content {} : {}", key, value));
            }
        } else {
            tv.output_expert.push("Content : none".to_string());
        }
    } else if code_hash == vote_proposal_hash {
        let vote_proposal = VoteProposalData::try_from_slice(
            &tx.data()
                .ok_or_else(|| Error::from(ErrorKind::InvalidData))?,
        )?;

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
                .ok_or_else(|| Error::from(ErrorKind::InvalidData))?,
        )?;

        tv.name = "Init Account 0".to_string();

        tv.output.extend(vec![
            format!("Type : Reveal PK"),
            format!("Public key : {}", public_key),
        ]);

        tv.output_expert
            .extend(vec![format!("Public key : {}", public_key)]);
    } else if code_hash == update_vp_hash {
        let transfer = UpdateVp::try_from_slice(
            &tx.data()
                .ok_or_else(|| Error::from(ErrorKind::InvalidData))?,
        )?;

        tv.name = "Update VP 0".to_string();

        let extra = tx
            .get_section(&transfer.vp_code_hash)
            .and_then(Section::extra_data_sec)
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
        let transfer = Transfer::try_from_slice(
            &tx.data()
                .ok_or_else(|| Error::from(ErrorKind::InvalidData))?,
        )?;
        // To facilitate lookups of MASP AssetTypes
        let mut asset_types = HashMap::new();
        let builder = if let Some(shielded_hash) = transfer.shielded {
            tx.sections.iter().find_map(|x| match x {
                Section::MaspBuilder(builder)
                    if builder.target == shielded_hash =>
                {
                    for (addr, epoch) in &builder.asset_types {
                        asset_types.insert(
                            make_asset_type(*epoch, addr),
                            (addr.clone(), *epoch),
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
        if transfer.source != masp() {
            tv.output.push(format!("Sender : {}", transfer.source));
            if transfer.target == masp() {
                make_ledger_amount_addr(
                    &mut tv.output,
                    transfer.amount,
                    &transfer.token,
                    "Sending ",
                );
            }
        } else if let Some(builder) = builder {
            for input in builder.builder.sapling_inputs() {
                let vk = ExtendedViewingKey::from(*input.key());
                tv.output.push(format!("Sender : {}", vk));
                make_ledger_amount_asset(
                    &mut tv.output,
                    input.value(),
                    &input.asset_type(),
                    &asset_types,
                    "Sending ",
                );
            }
        }
        if transfer.target != masp() {
            tv.output.push(format!("Destination : {}", transfer.target));
            if transfer.source == masp() {
                make_ledger_amount_addr(
                    &mut tv.output,
                    transfer.amount,
                    &transfer.token,
                    "Receiving ",
                );
            }
        } else if let Some(builder) = builder {
            for output in builder.builder.sapling_outputs() {
                let pa = PaymentAddress::from(output.address());
                tv.output.push(format!("Destination : {}", pa));
                make_ledger_amount_asset(
                    &mut tv.output,
                    output.value(),
                    &output.asset_type(),
                    &asset_types,
                    "Receiving ",
                );
            }
        }
        if transfer.source != masp() && transfer.target != masp() {
            make_ledger_amount_addr(
                &mut tv.output,
                transfer.amount,
                &transfer.token,
                "",
            );
        }

        tv.output_expert.extend(vec![
            format!("Source : {}", transfer.source),
            format!("Target : {}", transfer.target),
            format!("Token : {}", transfer.token),
            format!("Amount : {}", transfer.amount),
        ]);
    } else if code_hash == ibc_hash {
        let msg = IbcMessage::decode(
            tx.data()
                .ok_or_else(|| Error::from(ErrorKind::InvalidData))?
                .as_ref(),
        )
        .map_err(|x| Error::new(ErrorKind::Other, x))?;

        tv.name = "IBC 0".to_string();
        tv.output.push("Type : IBC".to_string());

        if let Ics26Envelope::Ics20Msg(transfer) = msg.0 {
            let transfer_token = transfer
                .token
                .as_ref()
                .map(|x| format!("{} {}", x.amount, x.denom))
                .unwrap_or_else(|| "(none)".to_string());
            tv.output.extend(vec![
                format!("Source port : {}", transfer.source_port),
                format!("Source channel : {}", transfer.source_channel),
                format!("Token : {}", transfer_token),
                format!("Sender : {}", transfer.sender),
                format!("Receiver : {}", transfer.receiver),
                format!("Timeout height : {}", transfer.timeout_height),
                format!("Timeout timestamp : {}", transfer.timeout_timestamp),
            ]);
            tv.output_expert.extend(vec![
                format!("Source port : {}", transfer.source_port),
                format!("Source channel : {}", transfer.source_channel),
                format!("Token : {}", transfer_token),
                format!("Sender : {}", transfer.sender),
                format!("Receiver : {}", transfer.receiver),
                format!("Timeout height : {}", transfer.timeout_height),
                format!("Timeout timestamp : {}", transfer.timeout_timestamp),
            ]);
        } else {
            for line in format!("{:#?}", msg).split('\n') {
                let stripped = line.trim_start();
                tv.output.push(format!("Part : {}", stripped));
                tv.output_expert.push(format!("Part : {}", stripped));
            }
        }
    } else if code_hash == bond_hash {
        let bond = pos::Bond::try_from_slice(
            &tx.data()
                .ok_or_else(|| Error::from(ErrorKind::InvalidData))?,
        )?;

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
            format!("Amount : {}", bond.amount),
        ]);

        tv.output_expert.extend(vec![
            format!("Source : {}", bond_source),
            format!("Validator : {}", bond.validator),
            format!("Amount : {}", bond.amount),
        ]);
    } else if code_hash == unbond_hash {
        let unbond = pos::Unbond::try_from_slice(
            &tx.data()
                .ok_or_else(|| Error::from(ErrorKind::InvalidData))?,
        )?;

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
            format!("Amount : {}", unbond.amount),
        ]);

        tv.output_expert.extend(vec![
            format!("Source : {}", unbond_source),
            format!("Validator : {}", unbond.validator),
            format!("Amount : {}", unbond.amount),
        ]);
    } else if code_hash == withdraw_hash {
        let withdraw = pos::Withdraw::try_from_slice(
            &tx.data()
                .ok_or_else(|| Error::from(ErrorKind::InvalidData))?,
        )?;

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
                .ok_or_else(|| Error::from(ErrorKind::InvalidData))?,
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
        tv.output_expert.extend(vec![
            format!("Timestamp : {}", tx.header.timestamp.0),
            format!("PK : {}", wrapper.pk),
            format!("Epoch : {}", wrapper.epoch),
            format!("Gas limit : {}", Amount::from(wrapper.gas_limit)),
            format!("Fee token : {}", wrapper.fee.token),
        ]);
        if let Some(token) = tokens.get(&wrapper.fee.token) {
            tv.output_expert
                .push(format!("Fee amount : {} {}", token, wrapper.fee.amount));
        } else {
            tv.output_expert
                .push(format!("Fee amount : {}", wrapper.fee.amount));
        }
    }

    // Finally, index each line and break those that are too long
    format_outputs(&mut tv.output);
    format_outputs(&mut tv.output_expert);
    Ok(tv)
}
