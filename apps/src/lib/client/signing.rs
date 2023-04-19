//! Helpers for making digital signatures using cryptographic keys from the
//! wallet.

use borsh::{BorshSerialize, BorshDeserialize};
use namada::ledger::parameters::storage as parameter_storage;
use namada::proto::{Data, Code, Tx, Section, Signature};
use namada::types::address::{tokens, Address, ImplicitAddress};
use namada::types::key::*;
use namada::types::storage::Epoch;
use namada::types::token;
use namada::types::token::{Transfer, Amount};
use namada::types::transaction::{hash_tx, pos, Fee, WrapperTx, MIN_FEE, InitAccount, InitValidator, UpdateVp};
use namada::types::transaction::TxType;
use namada::types::transaction::decrypted::DecryptedTx;
use namada::types::hash::Hash;
use sha2::{Digest, Sha256};
use data_encoding::HEXLOWER;
use serde::{Deserialize, Serialize};
use std::io::{Error, ErrorKind, Write};
use std::collections::BTreeMap;
use namada::types::ibc::data::IbcMessage;
use namada::types::transaction::governance::{
    InitProposalData, VoteProposalData,
};
use namada::types::address::masp;
use namada::ibc::core::ics26_routing::msgs::Ics26Envelope;
use std::env;
use std::fs::File;
use masp_primitives::transaction::components::sapling::fees::{OutputView, InputView};
use namada::types::masp::{PaymentAddress, ExtendedViewingKey};

use super::rpc;
use crate::cli::context::{WalletAddress, WalletKeypair};
use crate::cli::{self, args, Context};
use crate::client::tendermint_rpc_types::TxBroadcastData;
use crate::facade::tendermint_config::net::Address as TendermintAddress;
use crate::facade::tendermint_rpc::HttpClient;
use crate::wallet::Wallet;
use crate::client::tx::{
    TX_BOND_WASM, TX_CHANGE_COMMISSION_WASM, TX_IBC_WASM, TX_INIT_ACCOUNT_WASM,
    TX_INIT_PROPOSAL, TX_INIT_VALIDATOR_WASM, TX_REVEAL_PK, TX_TRANSFER_WASM,
    TX_UNBOND_WASM, TX_UPDATE_VP_WASM, TX_VOTE_PROPOSAL, TX_WITHDRAW_WASM,
    VP_USER_WASM,
};

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
        TxSigningKey::SecretKey(signing_key) => {
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
    mut tx: Tx,
    args: &args::Tx,
    default: TxSigningKey,
    #[cfg(not(feature = "mainnet"))] requires_pow: bool,
) -> (Context, TxBroadcastData) {
    let keypair = tx_signer(&mut ctx, args, default).await;
    // Sign over the transacttion data
    tx.add_section(Section::Signature(Signature::new(tx.data_sechash(), &keypair)));
    // Sign over the transaction code
    tx.add_section(Section::Signature(Signature::new(tx.code_sechash(), &keypair)));

    let epoch = match args.epoch {
        Some(epoch) if args.unchecked => epoch,
        _ => {
            rpc::query_epoch(args::Query {
                ledger_address: args.ledger_address.clone(),
            })
                .await
        }
    };
    let broadcast_data = if args.dry_run {
        tx.header = TxType::Decrypted(DecryptedTx::Decrypted {
            code_hash: tx.code_sechash().clone(),
            data_hash: tx.data_sechash().clone(),
            header_hash: Hash::default(),
            #[cfg(not(feature = "mainnet"))]
            // To be able to dry-run testnet faucet withdrawal, pretend 
            // that we got a valid PoW
            has_valid_pow: true,
        });
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
    (ctx, broadcast_data)
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
        pow_solution.clone(),
    )));
    // Then sign over the bound wrapper
    tx.add_section(Section::Signature(Signature::new(&tx.header_hash(), keypair)));

    // Attempt to decode the construction
    if let Ok(path) = env::var(ENV_VAR_LEDGER_LOG_PATH) {
        let mut tx = tx.clone();
        // Contract the large data blobs in the transaction
        tx.wallet_filter();
        // Convert the transaction to Ledger format
        let decoding = to_ledger_vector(ctx, &tx)
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
        writeln!(f, "{:x?},", tx)
            .expect("unable to write test vector to file");
    }
    
    // Remove all the sensitive sections
    tx.protocol_filter();
    // Encrypt all sections not relating to the header
    tx.encrypt(&Default::default());
    // We use this to determine when the wrapper tx makes it on-chain
    let wrapper_hash = tx.header_hash().to_string();
    // We use this to determine when the decrypted inner tx makes it
    // on-chain
    let decrypted_header = TxType::Decrypted(DecryptedTx::Decrypted {
        data_hash: *tx.data_sechash(),
        code_hash: *tx.code_sechash(),
        header_hash: tx.header_hash(),
        has_valid_pow: pow_solution.is_some(),
    });
    let decrypted_hash = Hash(
        decrypted_header.hash(&mut Sha256::new()).finalize_reset().into()
    ).to_string();
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

/// Adds a Ledger output line describing a given transaction amount
fn make_ledger_amount(output: &mut Vec<String>, amount: Amount, token: &Address, prefix: &str) {
    // To facilitate lookups of human-readable token names
    let tokens = tokens();
    
    if let Some(token) = tokens.get(&token) {
        output
            .push(format!("3 | {}Amount: {} {}", prefix, token, amount));
    } else {
        output.extend(vec![
            format!("3 | {}Token: {}", prefix, token),
            format!("4 | {}Amount: {}", prefix, amount),
        ]);
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
        blob: HEXLOWER.encode(
            &tx.try_to_vec().expect("unable to serialize transaction")
        ),
        index: 0,
        valid: true,
        name: "Custom 0".to_string(),
        ..Default::default()
    };

    let mut j = 0;
    let code_hash = tx
        .get_section(tx.code_sechash())
        .expect("expected tx code section to be present")
        .code_sec()
        .expect("expected section to have code tag")
        .code
        .hash();
    tv.output_expert.push(format!(
        "{} | Code hash: {}",
        j,
        HEXLOWER.encode(&code_hash.0)
    ));
    j += 1;

    if code_hash == init_account_hash {
        let init_account = InitAccount::try_from_slice(
            &tx.data()
                .clone()
                .ok_or_else(|| Error::from(ErrorKind::InvalidData))?,
        )?;

        tv.name = "Init Account 0".to_string();

        let extra = tx.get_section(&init_account.vp_code)
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
            format!("0 | Type: Init Account"),
            format!("1 | Public key: {}", init_account.public_key),
            format!("2 | VP type: {}", vp_code),
        ]);

        tv.output_expert.extend(vec![
            format!("{} | Public key: {}", j, init_account.public_key),
            format!("{} | VP type: {}", j + 1, HEXLOWER.encode(&extra.0)),
        ]);
        j += 2;
    } else if code_hash == init_validator_hash {
        let init_validator = InitValidator::try_from_slice(
            &tx.data().ok_or_else(|| Error::from(ErrorKind::InvalidData))?,
        )?;

        tv.name = "Init Validator 0".to_string();

        let extra = tx.get_section(&init_validator.validator_vp_code)
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
                HEXLOWER.encode(&extra.0)
            ),
        ]);
        j += 7;
    } else if code_hash == init_proposal_hash {
        let init_proposal_data = InitProposalData::try_from_slice(
            &tx.data().ok_or_else(|| Error::from(ErrorKind::InvalidData))?,
        )?;

        tv.name = "Init Proposal 0".to_string();

        let init_proposal_data_id = init_proposal_data
            .id
            .as_ref()
            .map(u64::to_string)
            .unwrap_or_else(|| "(none)".to_string());
        let extra = init_proposal_data.proposal_code.map(|vp_code| {
            tx.get_section(&vp_code)
                .and_then(Section::extra_data_sec)
                .expect("unable to load vp code")
                .code
                .hash()
        });
        let proposal_code = extra.map_or("(none)".to_string(), |x| HEXLOWER.encode(&x.0));
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
    } else if code_hash == vote_proposal_hash {
        let vote_proposal = VoteProposalData::try_from_slice(
            &tx.data().ok_or_else(|| Error::from(ErrorKind::InvalidData))?,
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
    } else if code_hash == reveal_pk_hash {
        let public_key = common::PublicKey::try_from_slice(
            &tx.data().ok_or_else(|| Error::from(ErrorKind::InvalidData))?,
        )?;

        tv.name = "Init Account 0".to_string();

        tv.output.extend(vec![
            format!("0 | Type: Reveal PK"),
            format!("1 | Public key: {}", public_key),
        ]);

        tv.output_expert
            .extend(vec![format!("{} | Public key: {}", j, public_key)]);
        j += 1;
    } else if code_hash == update_vp_hash {
        let transfer = UpdateVp::try_from_slice(
            &tx.data().ok_or_else(|| Error::from(ErrorKind::InvalidData))?,
        )?;

        tv.name = "Update VP 0".to_string();

        let extra = tx.get_section(&transfer.vp_code)
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
            format!("0 | Type: Update VP"),
            format!("1 | Address: {}", transfer.addr),
            format!("2 | VP type: {}", vp_code),
        ]);

        tv.output_expert.extend(vec![
            format!("{} | Address: {}", j, transfer.addr),
            format!("{} | VP type: {}", j + 1, HEXLOWER.encode(&extra.0)),
        ]);
        j += 2;
    } else if code_hash == transfer_hash {
        let transfer = Transfer::try_from_slice(
            &tx.data().ok_or_else(|| Error::from(ErrorKind::InvalidData))?,
        )?;
        let builder = if let Some(shielded_hash) = transfer.shielded {
            tx.sections.iter().find_map(|x| {
                match x {
                    Section::MaspBuilder(builder) if builder.target == shielded_hash => {
                        Some(builder)
                    },
                    _ => None,
                }
            })
        } else {
            None
        };

        tv.name = "Transfer 0".to_string();

        tv.output.push(format!("0 | Type: Transfer"));
        if transfer.source != masp() {
            tv.output.push(format!("1 | Sender: {}", transfer.source));
            if transfer.target == masp() {
                make_ledger_amount(&mut tv.output, transfer.amount, &transfer.token, "Sending ");
            }
        } else if let Some(builder) = builder {
            for input in builder.builder.sapling_inputs() {
                let vk = ExtendedViewingKey::from(input.key().clone());
                tv.output.push(format!("1 | Sender: {}", vk));
                tv.output
                    .push(format!("3 | Sending: {} {}", input.asset_type(), Amount::from(input.value())));
            }
        }
        if transfer.target != masp() {
            tv.output.push(format!("2 | Destination: {}", transfer.target));
            if transfer.source == masp() {
                make_ledger_amount(&mut tv.output, transfer.amount, &transfer.token, "Receiving ");
            }
        } else if let Some(builder) = builder {
            for output in builder.builder.sapling_outputs() {
                let pa = PaymentAddress::from(output.address().clone());
                tv.output.push(format!("1 | Destination: {}", pa));
                tv.output
                    .push(format!("3 | Receiving: {} {}", output.asset_type(), Amount::from(output.value())));
            }
        }
        if transfer.source != masp() && transfer.target != masp() {
            make_ledger_amount(&mut tv.output, transfer.amount, &transfer.token, "");
        }

        tv.output_expert.extend(vec![
            format!("{} | Source: {}", j, transfer.source),
            format!("{} | Target: {}", j + 1, transfer.target),
            format!("{} | Token: {}", j + 2, transfer.token),
            format!("{} | Amount: {}", j + 3, transfer.amount),
        ]);
    } else if code_hash == ibc_hash {
        let msg = IbcMessage::decode(
            tx.data()
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
    } else if code_hash == bond_hash {
        let bond = pos::Bond::try_from_slice(
            &tx.data().ok_or_else(|| Error::from(ErrorKind::InvalidData))?,
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
    } else if code_hash == unbond_hash {
        let unbond = pos::Unbond::try_from_slice(
            &tx.data().ok_or_else(|| Error::from(ErrorKind::InvalidData))?,
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
    } else if code_hash == withdraw_hash {
        let withdraw = pos::Withdraw::try_from_slice(
            &tx.data().ok_or_else(|| Error::from(ErrorKind::InvalidData))?,
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
    } else if code_hash == change_commission_hash {
        let commission_change = pos::CommissionChange::try_from_slice(
            &tx.data().ok_or_else(|| Error::from(ErrorKind::InvalidData))?,
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

    if let Some(wrapper) = tx.header.wrapper() {
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
    }
    Ok(tv)
}
