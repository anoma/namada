//! Helpers for making digital signatures using cryptographic keys from the
//! wallet.

use std::collections::BTreeMap;
use std::env;
use std::fs::File;
use std::io::{Error, ErrorKind, Write};

use borsh::{BorshDeserialize, BorshSerialize};
use data_encoding::HEXLOWER;
use namada::ibc::core::ics26_routing::msgs::Ics26Envelope;
use namada::ledger::parameters::storage as parameter_storage;
use namada::proto::Tx;
use namada::proto::SignedTxData;
use namada::types::address::{tokens, Address, ImplicitAddress};
use namada::types::ibc::data::IbcMessage;
use namada::types::key::*;
use namada::types::storage::Epoch;
use namada::types::token;
use namada::types::token::{Amount, Transfer};
use namada::types::transaction::TxType;
use namada::types::transaction::governance::{
    InitProposalData, VoteProposalData,
};
use namada::types::transaction::{
    hash_tx, pos, Fee, InitAccount, InitValidator, UpdateVp, WrapperTx, MIN_FEE,
};
use prost::Message;
use serde::{Deserialize, Serialize};

use super::rpc;
use crate::cli::context::{WalletAddress, WalletKeypair};
use crate::cli::{self, args, Context};
use crate::client::tendermint_rpc_types::TxBroadcastData;
use crate::client::tx::{
    TX_BOND_WASM, TX_CHANGE_COMMISSION_WASM, TX_IBC_WASM, TX_INIT_ACCOUNT_WASM,
    TX_INIT_PROPOSAL, TX_INIT_VALIDATOR_WASM, TX_REVEAL_PK, TX_TRANSFER_WASM,
    TX_UNBOND_WASM, TX_UPDATE_VP_WASM, TX_VOTE_PROPOSAL, TX_WITHDRAW_WASM,
    VP_USER_WASM,
};
use crate::facade::tendermint_config::net::Address as TendermintAddress;
use crate::facade::tendermint_rpc::HttpClient;
use crate::wallet::Wallet;

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
        TxSigningKey::SecretKey(signing_key) => {
            // Check if the signing key needs to reveal its PK first
            let pk: common::PublicKey = signing_key.ref_to();
            super::tx::reveal_pk_if_needed(ctx, &pk, args).await;
            signing_key
        }
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
    tx: Tx,
    args: &args::Tx,
    default: TxSigningKey,
    #[cfg(not(feature = "mainnet"))] requires_pow: bool,
) -> (Context, TxBroadcastData) {
    let keypair = tx_signer(&mut ctx, args, default).await;
    let unsigned_tx = tx.clone();
    let tx = tx.sign(&keypair);

    let epoch = if let Some(epoch) = args.epoch {
        epoch
    } else {
        rpc::query_epoch(args::Query {
            ledger_address: args.ledger_address.clone(),
        })
        .await
    };
    let broadcast_data = if args.dry_run {
        TxBroadcastData::DryRun(tx)
    } else {
        sign_wrapper(
            &ctx,
            args,
            epoch,
            unsigned_tx,
            tx,
            &keypair,
            #[cfg(not(feature = "mainnet"))]
            requires_pow,
        )
        .await
    };
    (ctx, broadcast_data)
}

/// Env. var specifying where to store signing test vectors
const ENV_VAR_TEST_VECTOR_PATH: &str = "NAMADA_TEST_VECTOR_PATH";

/// Create a wrapper tx from a normal tx. Get the hash of the
/// wrapper and its payload which is needed for monitoring its
/// progress on chain.
pub async fn sign_wrapper(
    ctx: &Context,
    args: &args::Tx,
    epoch: Epoch,
    unsigned_tx: Tx,
    tx: Tx,
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
    let wrapper_tx = WrapperTx::new(
        Fee {
            amount: fee_amount,
            token: fee_token,
        },
        keypair,
        epoch,
        args.gas_limit.clone(),
        #[cfg(not(feature = "mainnet"))]
        pow_solution,
    );

    // Attempt to decode the construction
    if let Ok(path) = env::var(ENV_VAR_TEST_VECTOR_PATH) {
        let mut unsigned_tx_bytes = vec![];
        unsigned_tx
            .signing_tx()
            .encode(&mut unsigned_tx_bytes)
            .expect("failed to serialize transaction");

        let payload = (unsigned_tx_bytes.clone(), wrapper_tx.clone())
            .try_to_vec()
            .expect("failed to serialize transaction");
        println!("Step 0 (Entire payload sent to ledger): {}", HEXLOWER.encode(&payload));
        println!("Step 1 (Extract Unsigned Inner Tx Bytes from Payload): {}", HEXLOWER.encode(&unsigned_tx_bytes));
        let tx_hash = hash_tx(&unsigned_tx_bytes).0;
        println!("Step 2 (SHA256 Hash of Step 1): {}", HEXLOWER.encode(&tx_hash));
        println!("Step 3 (Signing Key, 1st byte == 00 => Ed25519 key): {}", keypair);
        let sig = common::SigScheme::sign(keypair, tx_hash);
        let sig_bytes = sig.try_to_vec().expect("Failed to encode signature");
        println!("Step 3 (Signature from Step 2&3, 1st byte == 00 => Ed25519 signature): {}", HEXLOWER.encode(&sig_bytes));
        let signed_tx_data =
            SignedTxData { data: unsigned_tx.data, sig: sig.clone() }
        .try_to_vec()
            .expect("Encoding transaction data shouldn't fail");
        println!("Step 4 (Concatenate data field of step 1 and signature from step 3): {}", HEXLOWER.encode(&signed_tx_data));
        let signed_inner_tx = Tx {
            code: unsigned_tx.code,
            data: Some(signed_tx_data),
            extra: unsigned_tx.extra,
            timestamp: unsigned_tx.timestamp,
            inner_tx: unsigned_tx.inner_tx,
        };
        let mut signed_inner_tx_bytes = vec![];
        signed_inner_tx
            .signing_tx()
            .encode(&mut signed_inner_tx_bytes)
            .expect("failed to serialize transaction");
        println!("Step 5 (Signed Inner Tx Bytes): {}", HEXLOWER.encode(&signed_inner_tx_bytes));

        let unbound_wrapper_tx_bytes = wrapper_tx
            .try_to_vec()
            .expect("Encoding transaction data shouldn't fail");
        println!("Step 0 (Extract Unbound Wrapper Tx Bytes from Payload): {}", HEXLOWER.encode(&unbound_wrapper_tx_bytes));
        let tx_hash = hash_tx(&signed_inner_tx_bytes).0;
        println!("Step 2 (Signed Inner Tx Bytes SHA256 Hash): {}", HEXLOWER.encode(&tx_hash));
        let bound_wrapper_tx_bytes = wrapper_tx
            .clone()
            .bind(tx.clone())
            .try_to_vec()
            .expect("Encoding transaction data shouldn't fail");
        println!("Step 2 (Bound Wrapper Tx Bytes): {}", HEXLOWER.encode(&bound_wrapper_tx_bytes));
        let wrapped_bound_wrapper_tx_bytes = TxType::Wrapper(
            wrapper_tx
                .clone()
                .bind(tx.clone()))
            .try_to_vec()
            .expect("Encoding transaction data shouldn't fail");
        println!("Step 3&4 (Wrapped Bound Wrapper Tx Bytes): {}",
                 HEXLOWER.encode(&wrapped_bound_wrapper_tx_bytes));
        let mut outer_tx_bytes = vec![];
        Tx::new(vec![], Some(wrapped_bound_wrapper_tx_bytes.clone()))
            .signing_tx()
            .encode(&mut outer_tx_bytes)
            .expect("Encoding transaction data shouldn't fail");
        println!("Step 5 (Outer Tx Bytes): {}", HEXLOWER.encode(&outer_tx_bytes));
        let outer_tx_hash = hash_tx(&outer_tx_bytes).0;
        println!("Step 6 (Outer Tx SHA256 Hash): {}", HEXLOWER.encode(&outer_tx_hash));
        println!("Step 6 (Signing Key, 1st byte == 00 => Ed25519 key): {}", keypair);
        let outer_sig = common::SigScheme::sign(keypair, outer_tx_hash);
        let outer_sig_bytes = outer_sig.try_to_vec().expect("Failed to encode signature");
        println!("Step 6 (Outer Tx Signature, 1st byte == 00 => Ed25519 signature): {}", HEXLOWER.encode(&outer_sig_bytes));
        
        let decoding = decode_tx(
            ctx,
            &(unsigned_tx_bytes, wrapper_tx.clone())
                .try_to_vec()
                .expect("failed to serialize transaction"),
        )
        .expect("unable to decode transaction");
        let output = serde_json::to_string(&decoding)
            .expect("failed to serialize decoding");
        let mut f = File::options()
            .append(true)
            .create(true)
            .open(path)
            .expect("failed to open test vector file");
        writeln!(f, "{},", output)
            .expect("unable to write test vector to file");
    }

    // Bind the inner transaction to the wrapper
    let wrapper_tx = wrapper_tx.bind(tx.clone());

    // Then sign over the bound wrapper
    let mut stx = wrapper_tx
        .sign(keypair)
        .expect("Wrapper tx signing keypair should be correct");
    // Then encrypt and attach the payload to the wrapper
    stx = stx.attach_inner_tx(
        &tx,
        // TODO: Actually use the fetched encryption key
        Default::default(),
    );
    // We use this to determine when the wrapper tx makes it on-chain
    let wrapper_hash = hash_tx(&wrapper_tx.try_to_vec().unwrap()).to_string();
    // We use this to determine when the decrypted inner tx makes it
    // on-chain
    let decrypted_hash = wrapper_tx.tx_hash.to_string();
    TxBroadcastData::Wrapper {
        tx: stx,
        wrapper_hash,
        decrypted_hash,
    }
}

#[derive(Default, Serialize, Deserialize)]
struct TestVector {
    blob: String,
    index: u64,
    name: String,
    output: Vec<String>,
    output_expert: Vec<String>,
    valid: bool,
}

fn decode_tx(
    ctx: &Context,
    tx_bytes: &[u8],
) -> Result<TestVector, std::io::Error> {
    let (tx, wrapper): (Vec<u8>, WrapperTx) =
        BorshDeserialize::try_from_slice(tx_bytes)?;
    let tx: Tx = Tx::try_from(tx.as_slice())
        .map_err(|x| Error::new(ErrorKind::Other, x))?;
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

    let mut tv = TestVector {
        blob: HEXLOWER.encode(tx_bytes),
        index: 0,
        valid: true,
        name: "Custom 0".to_string(),
        ..Default::default()
    };

    let mut j = 0;
    tv.output_expert.push(format!(
        "{} | Code hash: {}",
        j,
        HEXLOWER.encode(&tx.code)
    ));
    j += 1;

    if tx.code == init_account_hash.0.to_vec() {
        let init_account = InitAccount::try_from_slice(
            &tx.data
                .clone()
                .ok_or_else(|| Error::from(ErrorKind::InvalidData))?,
        )?;

        tv.name = "Init Account 0".to_string();

        let vp_code = if tx.extra == user_hash.0.to_vec() {
            "User".to_string()
        } else {
            HEXLOWER.encode(&tx.extra)
        };

        tv.output.extend(vec![
            format!("0 | Type: Init Account"),
            format!("1 | Public key: {}", init_account.public_key),
            format!("2 | VP type: {}", vp_code),
        ]);

        tv.output_expert.extend(vec![
            format!("{} | Public key: {}", j, init_account.public_key),
            format!("{} | VP type: {}", j + 1, HEXLOWER.encode(&tx.extra)),
        ]);
        j += 2;
    } else if tx.code == init_validator_hash.0.to_vec() {
        let init_validator = InitValidator::try_from_slice(
            &tx.data.ok_or_else(|| Error::from(ErrorKind::InvalidData))?,
        )?;

        tv.name = "Init Validator 0".to_string();

        let vp_code = if tx.extra == user_hash.0.to_vec() {
            "User".to_string()
        } else {
            HEXLOWER.encode(&tx.extra)
        };

        tv.output.extend(vec![
            format!("0 | Type: Init Validator"),
            format!("1 | Account key: {}", init_validator.account_key),
            format!("2 | Consensus key: {}", init_validator.consensus_key),
            format!("3 | Protocol key: {}", init_validator.protocol_key),
            format!("4 | DKG key: {}", init_validator.dkg_key),
            format!("5 | Commission rate: {}", init_validator.commission_rate),
            format!(
                "6 | Maximum commission rate change: {}",
                init_validator.max_commission_rate_change
            ),
            format!("7 | Validator VP type: {}", vp_code,),
        ]);

        tv.output_expert.extend(vec![
            format!("{} | Account key: {}", j, init_validator.account_key),
            format!(
                "{} | Consensus key: {}",
                j + 1,
                init_validator.consensus_key
            ),
            format!(
                "{} | Protocol key: {}",
                j + 2,
                init_validator.protocol_key
            ),
            format!("{} | DKG key: {}", j + 3, init_validator.dkg_key),
            format!(
                "{} | Commission rate: {}",
                j + 4,
                init_validator.commission_rate
            ),
            format!(
                "{} | Maximum commission rate change: {}",
                j + 5,
                init_validator.max_commission_rate_change
            ),
            format!(
                "{} | Validator VP type: {}",
                j + 6,
                HEXLOWER.encode(&tx.extra)
            ),
        ]);
        j += 7;
    } else if tx.code == init_proposal_hash.0.to_vec() {
        let init_proposal_data = InitProposalData::try_from_slice(
            &tx.data.ok_or_else(|| Error::from(ErrorKind::InvalidData))?,
        )?;

        tv.name = "Init Proposal 0".to_string();

        let init_proposal_data_id = init_proposal_data
            .id
            .as_ref()
            .map(u64::to_string)
            .unwrap_or_else(|| "(none)".to_string());
        let proposal_code = HEXLOWER.encode(&tx.extra);
        tv.output.extend(vec![
            format!("0 | Type: Init proposal"),
            format!("1 | ID: {}", init_proposal_data_id),
            format!("2 | Author: {}", init_proposal_data.author),
            format!(
                "3 | Voting start epoch: {}",
                init_proposal_data.voting_start_epoch
            ),
            format!(
                "4 | Voting end epoch: {}",
                init_proposal_data.voting_end_epoch
            ),
            format!("5 | Grace epoch: {}", init_proposal_data.grace_epoch),
            format!("6 | Proposal code: {}", proposal_code),
        ]);
        let content: BTreeMap<String, String> =
            BorshDeserialize::try_from_slice(&init_proposal_data.content)?;
        if !content.is_empty() {
            for (key, value) in &content {
                tv.output.push(format!("7 | Content {}: {}", key, value));
            }
        } else {
            tv.output.push("7 | Content: (none)".to_string());
        }

        tv.output_expert.extend(vec![
            format!("{} | ID: {}", j, init_proposal_data_id),
            format!("{} | Author: {}", j + 1, init_proposal_data.author),
            format!(
                "{} | Voting start epoch: {}",
                j + 2,
                init_proposal_data.voting_start_epoch
            ),
            format!(
                "{} | Voting end epoch: {}",
                j + 3,
                init_proposal_data.voting_end_epoch
            ),
            format!(
                "{} | Grace epoch: {}",
                j + 4,
                init_proposal_data.grace_epoch
            ),
            format!("{} | Proposal code: {}", j + 5, proposal_code),
        ]);
        if !content.is_empty() {
            for (key, value) in content {
                tv.output_expert.push(format!(
                    "{} | Content {}: {}",
                    j + 6,
                    key,
                    value
                ));
            }
        } else {
            tv.output_expert.push(format!("{} | Content: none", j + 6));
        }
        j += 7;
    } else if tx.code_hash() == vote_proposal_hash.0 {
        let vote_proposal = VoteProposalData::try_from_slice(
            &tx.data.ok_or_else(|| Error::from(ErrorKind::InvalidData))?,
        )?;

        tv.name = "Vote Proposal 0".to_string();

        tv.output.extend(vec![
            format!("0 | Type: Vote Proposal"),
            format!("1 | ID: {}", vote_proposal.id),
            format!("2 | Vote: {}", vote_proposal.vote),
            format!("3 | Voter: {}", vote_proposal.voter),
        ]);
        for delegation in &vote_proposal.delegations {
            tv.output.push(format!("4 | Delegations: {}", delegation));
        }

        tv.output_expert.extend(vec![
            format!("{} | ID: {}", j, vote_proposal.id),
            format!("{} | Vote: {}", j + 1, vote_proposal.vote),
            format!("{} | Voter: {}", j + 2, vote_proposal.voter),
        ]);
        for delegation in vote_proposal.delegations {
            tv.output_expert.push(format!(
                "{} | Delegations: {}",
                j + 3,
                delegation
            ));
        }
        j += 4;
    } else if tx.code == reveal_pk_hash.0.to_vec() {
        let public_key = common::PublicKey::try_from_slice(
            &tx.data.ok_or_else(|| Error::from(ErrorKind::InvalidData))?,
        )?;

        tv.name = "Init Account 0".to_string();

        tv.output.extend(vec![
            format!("0 | Type: Reveal PK"),
            format!("1 | Public key: {}", public_key),
        ]);

        tv.output_expert
            .extend(vec![format!("{} | Public key: {}", j, public_key)]);
        j += 1;
    } else if tx.code == update_vp_hash.0.to_vec() {
        let transfer = UpdateVp::try_from_slice(
            &tx.data.ok_or_else(|| Error::from(ErrorKind::InvalidData))?,
        )?;

        tv.name = "Update VP 0".to_string();

        let vp_code = if tx.extra == user_hash.0.to_vec() {
            "User".to_string()
        } else {
            HEXLOWER.encode(&tx.extra)
        };

        tv.output.extend(vec![
            format!("0 | Type: Update VP"),
            format!("1 | Address: {}", transfer.addr),
            format!("2 | VP type: {}", vp_code),
        ]);

        tv.output_expert.extend(vec![
            format!("{} | Address: {}", j, transfer.addr),
            format!("{} | VP type: {}", j + 1, HEXLOWER.encode(&tx.extra)),
        ]);
        j += 2;
    } else if tx.code == transfer_hash.0.to_vec() {
        let transfer = Transfer::try_from_slice(
            &tx.data.ok_or_else(|| Error::from(ErrorKind::InvalidData))?,
        )?;

        tv.name = "Transfer 0".to_string();

        tv.output.extend(vec![
            format!("0 | Type: Transfer"),
            format!("1 | Sender: {}", transfer.source),
            format!("2 | Destination: {}", transfer.target),
        ]);
        if let Some(token) = tokens.get(&transfer.token) {
            tv.output
                .push(format!("3 | Amount: {} {}", token, transfer.amount));
            j += 3;
        } else {
            tv.output.extend(vec![
                format!("3 | Token: {}", transfer.token),
                format!("4 | Amount: {}", transfer.amount),
            ]);
            j += 4;
        }

        tv.output_expert.extend(vec![
            format!("{} | Source: {}", j, transfer.source),
            format!("{} | Target: {}", j + 1, transfer.target),
            format!("{} | Token: {}", j + 2, transfer.token),
            format!("{} | Amount: {}", j + 3, transfer.amount),
        ]);
    } else if tx.code == ibc_hash.0.to_vec() {
        let msg = IbcMessage::decode(
            tx.data
                .ok_or_else(|| Error::from(ErrorKind::InvalidData))?
                .as_ref(),
        )
        .map_err(|x| Error::new(ErrorKind::Other, x))?;

        tv.name = "IBC 0".to_string();
        tv.output.push("0 | Type: IBC".to_string());

        if let Ics26Envelope::Ics20Msg(transfer) = msg.0 {
            let transfer_token = transfer
                .token
                .as_ref()
                .map(|x| format!("{} {}", x.amount, x.denom))
                .unwrap_or_else(|| "(none)".to_string());
            tv.output.extend(vec![
                format!("1 | Source port: {}", transfer.source_port),
                format!("2 | Source channel: {}", transfer.source_channel),
                format!("3 | Token: {}", transfer_token),
                format!("4 | Sender: {}", transfer.sender),
                format!("5 | Receiver: {}", transfer.receiver),
                format!("6 | Timeout height: {}", transfer.timeout_height),
                format!(
                    "7 | Timeout timestamp: {}",
                    transfer.timeout_timestamp
                ),
            ]);
            tv.output_expert.extend(vec![
                format!("{} | Source port: {}", j, transfer.source_port),
                format!(
                    "{} | Source channel: {}",
                    j + 1,
                    transfer.source_channel
                ),
                format!("{} | Token: {}", j + 2, transfer_token),
                format!("{} | Sender: {}", j + 3, transfer.sender),
                format!("{} | Receiver: {}", j + 4, transfer.receiver),
                format!(
                    "{} | Timeout height: {}",
                    j + 5,
                    transfer.timeout_height
                ),
                format!(
                    "{} | Timeout timestamp: {}",
                    j + 6,
                    transfer.timeout_timestamp
                ),
            ]);
            j += 7;
        } else {
            for line in format!("{:#?}", msg).split('\n') {
                let stripped = line.trim_start();
                tv.output.push(format!("1 | {}", stripped));
                tv.output_expert.push(format!("{} | {}", j, stripped));
            }
            j += 1;
        }
    } else if tx.code == bond_hash.0.to_vec() {
        let bond = pos::Bond::try_from_slice(
            &tx.data.ok_or_else(|| Error::from(ErrorKind::InvalidData))?,
        )?;

        tv.name = "Bond 0".to_string();

        let bond_source = bond
            .source
            .as_ref()
            .map(Address::to_string)
            .unwrap_or_else(|| "(none)".to_string());
        tv.output.extend(vec![
            format!("0 | Type: Bond"),
            format!("1 | Source: {}", bond_source),
            format!("2 | Validator: {}", bond.validator),
            format!("3 | Amount: {}", bond.amount),
        ]);

        tv.output_expert.extend(vec![
            format!("{} | Source: {}", j, bond_source),
            format!("{} | Validator: {}", j + 1, bond.validator),
            format!("{} | Amount: {}", j + 2, bond.amount),
        ]);
        j += 3;
    } else if tx.code == unbond_hash.0.to_vec() {
        let unbond = pos::Unbond::try_from_slice(
            &tx.data.ok_or_else(|| Error::from(ErrorKind::InvalidData))?,
        )?;

        tv.name = "Unbond 0".to_string();

        let unbond_source = unbond
            .source
            .as_ref()
            .map(Address::to_string)
            .unwrap_or_else(|| "(none)".to_string());
        tv.output.extend(vec![
            format!("0 | Code: Unbond"),
            format!("1 | Source: {}", unbond_source),
            format!("2 | Validator: {}", unbond.validator),
            format!("3 | Amount: {}", unbond.amount),
        ]);

        tv.output_expert.extend(vec![
            format!("{} | Source: {}", j, unbond_source),
            format!("{} | Validator: {}", j + 1, unbond.validator),
            format!("{} | Amount: {}", j + 2, unbond.amount),
        ]);
        j += 3;
    } else if tx.code == withdraw_hash.0.to_vec() {
        let withdraw = pos::Withdraw::try_from_slice(
            &tx.data.ok_or_else(|| Error::from(ErrorKind::InvalidData))?,
        )?;

        tv.name = "Withdraw 0".to_string();

        let withdraw_source = withdraw
            .source
            .as_ref()
            .map(Address::to_string)
            .unwrap_or_else(|| "(none)".to_string());
        tv.output.extend(vec![
            format!("0 | Type: Withdraw"),
            format!("1 | Source: {}", withdraw_source),
            format!("2 | Validator: {}", withdraw.validator),
        ]);

        tv.output_expert.extend(vec![
            format!("{} | Source: {}", j, withdraw_source),
            format!("{} | Validator: {}", j + 1, withdraw.validator),
        ]);
        j += 2;
    } else if tx.code == change_commission_hash.0.to_vec() {
        let commission_change = pos::CommissionChange::try_from_slice(
            &tx.data.ok_or_else(|| Error::from(ErrorKind::InvalidData))?,
        )?;

        tv.name = "Change Commission 0".to_string();

        tv.output.extend(vec![
            format!("0 | Type: Change commission"),
            format!("1 | New rate: {}", commission_change.new_rate),
            format!("2 | Validator: {}", commission_change.validator),
        ]);

        tv.output_expert.extend(vec![
            format!("{} | New rate: {}", j, commission_change.new_rate),
            format!("{} | Validator: {}", j + 1, commission_change.validator),
        ]);
        j += 2;
    }

    tv.output_expert.extend(vec![
        format!("{} | Timestamp: {}", j, tx.timestamp.0),
        format!("{} | PK: {}", j + 1, wrapper.pk),
        format!("{} | Epoch: {}", j + 2, wrapper.epoch),
        format!("{} | Gas limit: {}", j + 3, Amount::from(wrapper.gas_limit)),
        format!("{} | Fee token: {}", j + 4, wrapper.fee.token),
    ]);
    if let Some(token) = tokens.get(&wrapper.fee.token) {
        tv.output_expert.push(format!(
            "{} | Fee amount: {} {}",
            j + 5,
            token,
            wrapper.fee.amount
        ));
    } else {
        tv.output_expert.push(format!(
            "{} | Fee amount: {}",
            j + 5,
            wrapper.fee.amount
        ));
    }
    Ok(tv)
}
