use std::collections::HashSet;
use std::env;
use std::fmt::Debug;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::PathBuf;

use async_std::io;
use async_std::io::prelude::WriteExt;
use borsh::{BorshDeserialize, BorshSerialize};
use data_encoding::HEXLOWER_PERMISSIVE;
use masp_proofs::prover::LocalTxProver;
use namada::ledger::governance::storage as gov_storage;

use namada::ledger::rpc::{TxBroadcastData, TxResponse};
use namada::ledger::signing::TxSigningKey;
use namada::ledger::wallet::{Wallet, WalletUtils};
use namada::ledger::{masp, tx};
use namada::proto::Tx;
use namada::types::address::Address;
use namada::types::governance::{
    OfflineProposal, OfflineVote, Proposal, ProposalVote, VoteType,
};
use namada::types::key::*;
use namada::types::storage::{Epoch, Key};
use namada::types::token;
use namada::types::transaction::governance::{
    InitProposalData, ProposalType, VoteProposalData,
};
use namada::types::transaction::InitValidator;
use rust_decimal::Decimal;
use tendermint_rpc::HttpClient;

use super::rpc;
use crate::cli::context::WalletAddress;
use crate::cli::{args, safe_exit, Context};
use crate::client::rpc::query_wasm_code_hash;
use crate::client::signing::find_keypair;
use crate::facade::tendermint_rpc::endpoint::broadcast::tx_sync::Response;
use crate::node::ledger::tendermint_node;
use crate::wallet::{gen_validator_keys, read_and_confirm_pwd, CliWalletUtils};

pub async fn submit_custom<C: namada::ledger::queries::Client + Sync>(
    client: &C,
    ctx: &mut Context,
    mut args: args::TxCustom,
) -> Result<(), tx::Error> {
    args.tx.chain_id = args
        .tx
        .chain_id
        .or_else(|| Some(ctx.config.ledger.chain_id.clone()));
    tx::submit_custom::<C, _>(client, &mut ctx.wallet, args).await
}

pub async fn submit_update_vp<C: namada::ledger::queries::Client + Sync>(
    client: &C,
    ctx: &mut Context,
    mut args: args::TxUpdateVp,
) -> Result<(), tx::Error> {
    args.tx.chain_id = args
        .tx
        .chain_id
        .or_else(|| Some(ctx.config.ledger.chain_id.clone()));
    tx::submit_update_vp::<C, _>(client, &mut ctx.wallet, args).await
}

pub async fn submit_init_account<C: namada::ledger::queries::Client + Sync>(
    client: &C,
    ctx: &mut Context,
    mut args: args::TxInitAccount,
) -> Result<(), tx::Error> {
    args.tx.chain_id = args
        .tx
        .chain_id
        .or_else(|| Some(ctx.config.ledger.chain_id.clone()));
    tx::submit_init_account::<C, _>(client, &mut ctx.wallet, args).await
}

pub async fn submit_init_validator<
    C: namada::ledger::queries::Client + Sync,
>(
    client: &C,
    mut ctx: Context,
    args::TxInitValidator {
        tx: tx_args,
        source,
        scheme,
        account_key,
        consensus_key,
        protocol_key,
        commission_rate,
        max_commission_rate_change,
        validator_vp_code_path,
        unsafe_dont_encrypt,
        tx_code_path: _,
    }: args::TxInitValidator,
) {
    let tx_args = args::Tx {
        chain_id: tx_args
            .clone()
            .chain_id
            .or_else(|| Some(ctx.config.ledger.chain_id.clone())),
        ..tx_args.clone()
    };
    let alias = tx_args
        .initialized_account_alias
        .as_ref()
        .cloned()
        .unwrap_or_else(|| "validator".to_string());

    let validator_key_alias = format!("{}-key", alias);
    let consensus_key_alias = format!("{}-consensus-key", alias);
    let account_key = account_key.unwrap_or_else(|| {
        println!("Generating validator account key...");
        let password = read_and_confirm_pwd(unsafe_dont_encrypt);
        ctx.wallet
            .gen_key(scheme, Some(validator_key_alias.clone()), password)
            .1
            .ref_to()
    });

    let consensus_key = consensus_key
        .map(|key| match key {
            common::SecretKey::Ed25519(_) => key,
            common::SecretKey::Secp256k1(_) => {
                eprintln!("Consensus key can only be ed25519");
                safe_exit(1)
            }
        })
        .unwrap_or_else(|| {
            println!("Generating consensus key...");
            let password = read_and_confirm_pwd(unsafe_dont_encrypt);
            ctx.wallet
                .gen_key(
                    // Note that TM only allows ed25519 for consensus key
                    SchemeType::Ed25519,
                    Some(consensus_key_alias.clone()),
                    password,
                )
                .1
        });

    let protocol_key = protocol_key;

    if protocol_key.is_none() {
        println!("Generating protocol signing key...");
    }
    // Generate the validator keys
    let validator_keys =
        gen_validator_keys(&mut ctx.wallet, protocol_key, scheme).unwrap();
    let protocol_key = validator_keys.get_protocol_keypair().ref_to();
    let dkg_key = validator_keys
        .dkg_keypair
        .as_ref()
        .expect("DKG sessions keys should have been created")
        .public();

    let vp_code_path = String::from_utf8(validator_vp_code_path).unwrap();
    let validator_vp_code_hash =
        query_wasm_code_hash::<C>(client, vp_code_path)
            .await
            .unwrap();

    // Validate the commission rate data
    if commission_rate > Decimal::ONE || commission_rate < Decimal::ZERO {
        eprintln!(
            "The validator commission rate must not exceed 1.0 or 100%, and \
             it must be 0 or positive"
        );
        if !tx_args.force {
            safe_exit(1)
        }
    }
    if max_commission_rate_change > Decimal::ONE
        || max_commission_rate_change < Decimal::ZERO
    {
        eprintln!(
            "The validator maximum change in commission rate per epoch must \
             not exceed 1.0 or 100%"
        );
        if !tx_args.force {
            safe_exit(1)
        }
    }
    let tx_code_hash =
        query_wasm_code_hash(client, args::TX_INIT_VALIDATOR_WASM)
            .await
            .unwrap();

    let data = InitValidator {
        account_key,
        consensus_key: consensus_key.ref_to(),
        protocol_key,
        dkg_key,
        commission_rate,
        max_commission_rate_change,
        validator_vp_code_hash,
    };
    let data = data.try_to_vec().expect("Encoding tx data shouldn't fail");
    let tx = Tx::new(
        tx_code_hash.to_vec(),
        Some(data),
        tx_args.chain_id.clone().unwrap(),
        tx_args.expiration,
    );
    let (mut ctx, result) = process_tx(
        client,
        ctx,
        &tx_args,
        tx,
        TxSigningKey::WalletAddress(source),
        #[cfg(not(feature = "mainnet"))]
        false,
    )
    .await
    .expect("expected process_tx to work");

    if !tx_args.dry_run {
        let (validator_address_alias, validator_address) = match &result[..] {
            // There should be 1 account for the validator itself
            [validator_address] => {
                let validator_address_alias = match tx_args
                    .initialized_account_alias
                {
                    Some(alias) => alias,
                    None => {
                        print!("Choose an alias for the validator address: ");
                        io::stdout().flush().await.unwrap();
                        let mut alias = String::new();
                        io::stdin().read_line(&mut alias).await.unwrap();
                        alias.trim().to_owned()
                    }
                };
                let validator_address_alias =
                    if validator_address_alias.is_empty() {
                        println!(
                            "Empty alias given, using {} as the alias.",
                            validator_address.encode()
                        );
                        validator_address.encode()
                    } else {
                        validator_address_alias
                    };
                if let Some(new_alias) = ctx.wallet.add_address(
                    validator_address_alias.clone(),
                    validator_address.clone(),
                ) {
                    println!(
                        "Added alias {} for address {}.",
                        new_alias,
                        validator_address.encode()
                    );
                }
                (validator_address_alias, validator_address.clone())
            }
            _ => {
                eprintln!("Expected one account to be created");
                safe_exit(1)
            }
        };
        // add validator address and keys to the wallet
        ctx.wallet
            .add_validator_data(validator_address, validator_keys);
        crate::wallet::save(&ctx.wallet)
            .unwrap_or_else(|err| eprintln!("{}", err));

        let tendermint_home = ctx.config.ledger.tendermint_dir();
        tendermint_node::write_validator_key(&tendermint_home, &consensus_key);
        tendermint_node::write_validator_state(tendermint_home);

        println!();
        println!(
            "The validator's addresses and keys were stored in the wallet:"
        );
        println!("  Validator address \"{}\"", validator_address_alias);
        println!("  Validator account key \"{}\"", validator_key_alias);
        println!("  Consensus key \"{}\"", consensus_key_alias);
        println!(
            "The ledger node has been setup to use this validator's address \
             and consensus key."
        );
    } else {
        println!("Transaction dry run. No addresses have been saved.")
    }
}

/// Shielded context file name
const FILE_NAME: &str = "shielded.dat";
const TMP_FILE_NAME: &str = "shielded.tmp";

#[derive(Debug, BorshSerialize, BorshDeserialize, Clone)]
pub struct CLIShieldedUtils {
    #[borsh_skip]
    context_dir: PathBuf,
}

impl CLIShieldedUtils {
    /// Initialize a shielded transaction context that identifies notes
    /// decryptable by any viewing key in the given set
    pub fn new(context_dir: PathBuf) -> masp::ShieldedContext<Self> {
        // Make sure that MASP parameters are downloaded to enable MASP
        // transaction building and verification later on
        let params_dir = masp::get_params_dir();
        let spend_path = params_dir.join(masp::SPEND_NAME);
        let convert_path = params_dir.join(masp::CONVERT_NAME);
        let output_path = params_dir.join(masp::OUTPUT_NAME);
        if !(spend_path.exists()
            && convert_path.exists()
            && output_path.exists())
        {
            println!("MASP parameters not present, downloading...");
            masp_proofs::download_parameters()
                .expect("MASP parameters not present or downloadable");
            println!("MASP parameter download complete, resuming execution...");
        }
        // Finally initialize a shielded context with the supplied directory
        let utils = Self { context_dir };
        masp::ShieldedContext {
            utils,
            ..Default::default()
        }
    }
}

impl Default for CLIShieldedUtils {
    fn default() -> Self {
        Self {
            context_dir: PathBuf::from(FILE_NAME),
        }
    }
}

impl masp::ShieldedUtils for CLIShieldedUtils {
    type C = tendermint_rpc::HttpClient;

    fn local_tx_prover(&self) -> LocalTxProver {
        if let Ok(params_dir) = env::var(masp::ENV_VAR_MASP_PARAMS_DIR) {
            let params_dir = PathBuf::from(params_dir);
            let spend_path = params_dir.join(masp::SPEND_NAME);
            let convert_path = params_dir.join(masp::CONVERT_NAME);
            let output_path = params_dir.join(masp::OUTPUT_NAME);
            LocalTxProver::new(&spend_path, &output_path, &convert_path)
        } else {
            LocalTxProver::with_default_location()
                .expect("unable to load MASP Parameters")
        }
    }

    /// Try to load the last saved shielded context from the given context
    /// directory. If this fails, then leave the current context unchanged.
    fn load(self) -> std::io::Result<masp::ShieldedContext<Self>> {
        // Try to load shielded context from file
        let mut ctx_file = File::open(self.context_dir.join(FILE_NAME))?;
        let mut bytes = Vec::new();
        ctx_file.read_to_end(&mut bytes)?;
        let mut new_ctx = masp::ShieldedContext::deserialize(&mut &bytes[..])?;
        // Associate the originating context directory with the
        // shielded context under construction
        new_ctx.utils = self;
        Ok(new_ctx)
    }

    /// Save this shielded context into its associated context directory
    fn save(&self, ctx: &masp::ShieldedContext<Self>) -> std::io::Result<()> {
        // TODO: use mktemp crate?
        let tmp_path = self.context_dir.join(TMP_FILE_NAME);
        {
            // First serialize the shielded context into a temporary file.
            // Inability to create this file implies a simultaneuous write is in
            // progress. In this case, immediately fail. This is unproblematic
            // because the data intended to be stored can always be re-fetched
            // from the blockchain.
            let mut ctx_file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(tmp_path.clone())?;
            let mut bytes = Vec::new();
            ctx.serialize(&mut bytes)
                .expect("cannot serialize shielded context");
            ctx_file.write_all(&bytes[..])?;
        }
        // Atomically update the old shielded context file with new data.
        // Atomicity is required to prevent other client instances from reading
        // corrupt data.
        std::fs::rename(tmp_path.clone(), self.context_dir.join(FILE_NAME))?;
        // Finally, remove our temporary file to allow future saving of shielded
        // contexts.
        std::fs::remove_file(tmp_path)?;
        Ok(())
    }
}

pub async fn submit_transfer(
    client: &HttpClient,
    mut ctx: Context,
    mut args: args::TxTransfer,
) -> Result<(), tx::Error> {
    args.tx.chain_id = args
        .tx
        .chain_id
        .or_else(|| Some(ctx.config.ledger.chain_id.clone()));
    tx::submit_transfer(client, &mut ctx.wallet, &mut ctx.shielded, args).await
}

pub async fn submit_ibc_transfer<C: namada::ledger::queries::Client + Sync>(
    client: &C,
    mut ctx: Context,
    mut args: args::TxIbcTransfer,
) -> Result<(), tx::Error> {
    args.tx.chain_id = args
        .tx
        .chain_id
        .or_else(|| Some(ctx.config.ledger.chain_id.clone()));
    tx::submit_ibc_transfer::<C, _>(client, &mut ctx.wallet, args).await
}

pub async fn submit_init_proposal<C: namada::ledger::queries::Client + Sync>(
    client: &C,
    mut ctx: Context,
    mut args: args::InitProposal,
) -> Result<(), tx::Error> {
    args.tx.chain_id = args
        .tx
        .chain_id
        .or_else(|| Some(ctx.config.ledger.chain_id.clone()));
    let file = File::open(&args.proposal_data).expect("File must exist.");
    let proposal: Proposal =
        serde_json::from_reader(file).expect("JSON was not well-formatted");

    let signer = WalletAddress::new(proposal.clone().author.to_string());
    let governance_parameters = rpc::get_governance_parameters(client).await;
    let current_epoch = rpc::query_and_print_epoch(client).await;

    if proposal.voting_start_epoch <= current_epoch
        || proposal.voting_start_epoch.0
            % governance_parameters.min_proposal_period
            != 0
    {
        println!("{}", proposal.voting_start_epoch <= current_epoch);
        println!(
            "{}",
            proposal.voting_start_epoch.0
                % governance_parameters.min_proposal_period
                == 0
        );
        eprintln!(
            "Invalid proposal start epoch: {} must be greater than current \
             epoch {} and a multiple of {}",
            proposal.voting_start_epoch,
            current_epoch,
            governance_parameters.min_proposal_period
        );
        if !args.tx.force {
            safe_exit(1)
        }
    } else if proposal.voting_end_epoch <= proposal.voting_start_epoch
        || proposal.voting_end_epoch.0 - proposal.voting_start_epoch.0
            < governance_parameters.min_proposal_period
        || proposal.voting_end_epoch.0 - proposal.voting_start_epoch.0
            > governance_parameters.max_proposal_period
        || proposal.voting_end_epoch.0 % 3 != 0
    {
        eprintln!(
            "Invalid proposal end epoch: difference between proposal start \
             and end epoch must be at least {} and at max {} and end epoch \
             must be a multiple of {}",
            governance_parameters.min_proposal_period,
            governance_parameters.max_proposal_period,
            governance_parameters.min_proposal_period
        );
        if !args.tx.force {
            safe_exit(1)
        }
    } else if proposal.grace_epoch <= proposal.voting_end_epoch
        || proposal.grace_epoch.0 - proposal.voting_end_epoch.0
            < governance_parameters.min_proposal_grace_epochs
    {
        eprintln!(
            "Invalid proposal grace epoch: difference between proposal grace \
             and end epoch must be at least {}",
            governance_parameters.min_proposal_grace_epochs
        );
        if !args.tx.force {
            safe_exit(1)
        }
    }

    if args.offline {
        let signer = ctx.get(&signer);
        let signing_key =
            find_keypair::<C, CliWalletUtils>(client, &mut ctx.wallet, &signer)
                .await?;
        let offline_proposal =
            OfflineProposal::new(proposal, signer, &signing_key);
        let proposal_filename = args
            .proposal_data
            .parent()
            .expect("No parent found")
            .join("proposal");
        let out = File::create(&proposal_filename).unwrap();
        match serde_json::to_writer_pretty(out, &offline_proposal) {
            Ok(_) => {
                println!(
                    "Proposal created: {}.",
                    proposal_filename.to_string_lossy()
                );
            }
            Err(e) => {
                eprintln!("Error while creating proposal file: {}.", e);
                safe_exit(1)
            }
        }
        Ok(())
    } else {
        let signer = ctx.get(&signer);
        let tx_data: Result<InitProposalData, _> = proposal.clone().try_into();
        let init_proposal_data = if let Ok(data) = tx_data {
            data
        } else {
            eprintln!("Invalid data for init proposal transaction.");
            safe_exit(1)
        };

        let balance = rpc::get_token_balance(
            client,
            &args.native_token,
            &proposal.author,
        )
        .await
        .unwrap_or_default();
        if balance
            < token::Amount::from(governance_parameters.min_proposal_fund)
        {
            eprintln!(
                "Address {} doesn't have enough funds.",
                &proposal.author
            );
            safe_exit(1);
        }

        if init_proposal_data.content.len()
            > governance_parameters.max_proposal_content_size as usize
        {
            eprintln!("Proposal content size too big.",);
            safe_exit(1);
        }

        let data = init_proposal_data
            .try_to_vec()
            .expect("Encoding proposal data shouldn't fail");
        let tx_code_hash = query_wasm_code_hash(client, args::TX_INIT_PROPOSAL)
            .await
            .unwrap();
        let tx = Tx::new(
            tx_code_hash.to_vec(),
            Some(data),
            ctx.config.ledger.chain_id.clone(),
            args.tx.expiration,
        );

        process_tx::<C>(
            client,
            ctx,
            &args.tx,
            tx,
            TxSigningKey::WalletAddress(signer),
            #[cfg(not(feature = "mainnet"))]
            false,
        )
        .await?;
        Ok(())
    }
}

pub async fn submit_vote_proposal<C: namada::ledger::queries::Client + Sync>(
    client: &C,
    mut ctx: Context,
    mut args: args::VoteProposal,
) -> Result<(), tx::Error> {
    args.tx.chain_id = args
        .tx
        .chain_id
        .or_else(|| Some(ctx.config.ledger.chain_id.clone()));
    let signer = if let Some(addr) = &args.tx.signer {
        addr
    } else {
        eprintln!("Missing mandatory argument --signer.");
        safe_exit(1)
    };

    // Construct vote
    let proposal_vote = match args.vote.to_ascii_lowercase().as_str() {
        "yay" => {
            if let Some(pgf) = args.proposal_pgf {
                let splits = pgf.trim().split_ascii_whitespace();
                let address_iter = splits.clone().into_iter().step_by(2);
                let cap_iter = splits.into_iter().skip(1).step_by(2);
                let mut set = HashSet::new();
                for (address, cap) in
                    address_iter.zip(cap_iter).map(|(addr, cap)| {
                        (
                            addr.parse()
                                .expect("Failed to parse pgf council address"),
                            cap.parse::<u64>()
                                .expect("Failed to parse pgf spending cap"),
                        )
                    })
                {
                    set.insert((address, cap.into()));
                }

                ProposalVote::Yay(VoteType::PGFCouncil(set))
            } else if let Some(eth) = args.proposal_eth {
                let mut splits = eth.trim().split_ascii_whitespace();
                // Sign the message
                let sigkey = splits
                    .next()
                    .expect("Expected signing key")
                    .parse::<common::SecretKey>()
                    .expect("Signing key parsing failed.");

                let msg = splits.next().expect("Missing message to sign");
                if splits.next().is_some() {
                    eprintln!("Unexpected argument after message");
                    safe_exit(1);
                }

                ProposalVote::Yay(VoteType::ETHBridge(common::SigScheme::sign(
                    &sigkey,
                    HEXLOWER_PERMISSIVE
                        .decode(msg.as_bytes())
                        .expect("Error while decoding message"),
                )))
            } else {
                ProposalVote::Yay(VoteType::Default)
            }
        }
        "nay" => ProposalVote::Nay,
        _ => {
            eprintln!("Vote must be either yay or nay");
            safe_exit(1);
        }
    };

    if args.offline {
        if !proposal_vote.is_default_vote() {
            eprintln!(
                "Wrong vote type for offline proposal. Just vote yay or nay!"
            );
            safe_exit(1);
        }
        let proposal_file_path =
            args.proposal_data.expect("Proposal file should exist.");
        let file = File::open(&proposal_file_path).expect("File must exist.");

        let proposal: OfflineProposal =
            serde_json::from_reader(file).expect("JSON was not well-formatted");
        let public_key = rpc::get_public_key(client, &proposal.address)
            .await
            .expect("Public key should exist.");
        if !proposal.check_signature(&public_key) {
            eprintln!("Proposal signature mismatch!");
            safe_exit(1)
        }

        let signing_key =
            find_keypair::<C, CliWalletUtils>(client, &mut ctx.wallet, signer)
                .await?;
        let offline_vote = OfflineVote::new(
            &proposal,
            proposal_vote,
            signer.clone(),
            &signing_key,
        );

        let proposal_vote_filename = proposal_file_path
            .parent()
            .expect("No parent found")
            .join(format!("proposal-vote-{}", &signer.to_string()));
        let out = File::create(&proposal_vote_filename).unwrap();
        match serde_json::to_writer_pretty(out, &offline_vote) {
            Ok(_) => {
                println!(
                    "Proposal vote created: {}.",
                    proposal_vote_filename.to_string_lossy()
                );
                Ok(())
            }
            Err(e) => {
                eprintln!("Error while creating proposal vote file: {}.", e);
                safe_exit(1)
            }
        }
    } else {
        let current_epoch = rpc::query_and_print_epoch(client).await;

        let voter_address = signer.clone();
        let proposal_id = args.proposal_id.unwrap();
        let proposal_start_epoch_key =
            gov_storage::get_voting_start_epoch_key(proposal_id);
        let proposal_start_epoch = rpc::query_storage_value::<C, Epoch>(
            client,
            &proposal_start_epoch_key,
        )
        .await;

        // Check vote type and memo
        let proposal_type_key = gov_storage::get_proposal_type_key(proposal_id);
        let proposal_type: ProposalType = rpc::query_storage_value::<
            C,
            ProposalType,
        >(client, &proposal_type_key)
        .await
        .unwrap_or_else(|| {
            panic!("Didn't find type of proposal id {} in storage", proposal_id)
        });

        if let ProposalVote::Yay(ref vote_type) = proposal_vote {
            if &proposal_type != vote_type {
                eprintln!(
                    "Expected vote of type {}, found {}",
                    proposal_type, args.vote
                );
                safe_exit(1);
            } else if let VoteType::PGFCouncil(set) = vote_type {
                // Check that addresses proposed as council are established and
                // are present in storage
                for (address, _) in set {
                    match address {
                        Address::Established(_) => {
                            let vp_key = Key::validity_predicate(address);
                            if !rpc::query_has_storage_key::<C>(client, &vp_key)
                                .await
                            {
                                eprintln!(
                                    "Proposed PGF council {} cannot be found \
                                     in storage",
                                    address
                                );
                                safe_exit(1);
                            }
                        }
                        _ => {
                            eprintln!(
                                "PGF council vote contains a non-established \
                                 address: {}",
                                address
                            );
                            safe_exit(1);
                        }
                    }
                }
            }
        }

        match proposal_start_epoch {
            Some(epoch) => {
                if current_epoch < epoch {
                    eprintln!(
                        "Current epoch {} is not greater than proposal start \
                         epoch {}",
                        current_epoch, epoch
                    );

                    if !args.tx.force {
                        safe_exit(1)
                    }
                }
                let mut delegations =
                    rpc::get_delegators_delegation(client, &voter_address)
                        .await;

                // Optimize by quering if a vote from a validator
                // is equal to ours. If so, we can avoid voting, but ONLY if we
                // are  voting in the last third of the voting
                // window, otherwise there's  the risk of the
                // validator changing his vote and, effectively, invalidating
                // the delgator's vote
                if !args.tx.force
                    && is_safe_voting_window(client, proposal_id, epoch).await?
                {
                    delegations = filter_delegations(
                        client,
                        delegations,
                        proposal_id,
                        &proposal_vote,
                    )
                    .await;
                }

                let tx_data = VoteProposalData {
                    id: proposal_id,
                    vote: proposal_vote,
                    voter: voter_address,
                    delegations: delegations.into_iter().collect(),
                };

                let chain_id = args.tx.chain_id.clone().unwrap();
                let expiration = args.tx.expiration;
                let data = tx_data
                    .try_to_vec()
                    .expect("Encoding proposal data shouldn't fail");
                let tx_code = args.tx_code_path;
                let tx = Tx::new(tx_code, Some(data), chain_id, expiration);

                process_tx::<C>(
                    client,
                    ctx,
                    &args.tx,
                    tx,
                    TxSigningKey::WalletAddress(signer.clone()),
                    #[cfg(not(feature = "mainnet"))]
                    false,
                )
                .await?;
                Ok(())
            }
            None => {
                eprintln!(
                    "Proposal start epoch for proposal id {} is not definied.",
                    proposal_id
                );
                if !args.tx.force { safe_exit(1) } else { Ok(()) }
            }
        }
    }
}

pub async fn submit_reveal_pk<C: namada::ledger::queries::Client + Sync>(
    client: &C,
    ctx: &mut Context,
    mut args: args::RevealPk,
) -> Result<(), tx::Error> {
    args.tx.chain_id = args
        .tx
        .chain_id
        .or_else(|| Some(ctx.config.ledger.chain_id.clone()));
    tx::submit_reveal_pk::<C, _>(client, &mut ctx.wallet, args).await
}

pub async fn reveal_pk_if_needed<C: namada::ledger::queries::Client + Sync>(
    client: &C,
    ctx: &mut Context,
    public_key: &common::PublicKey,
    args: &args::Tx,
) -> Result<bool, tx::Error> {
    let args = args::Tx {
        chain_id: args
            .clone()
            .chain_id
            .or_else(|| Some(ctx.config.ledger.chain_id.clone())),
        ..args.clone()
    };
    tx::reveal_pk_if_needed::<C, _>(client, &mut ctx.wallet, public_key, &args)
        .await
}

pub async fn has_revealed_pk<C: namada::ledger::queries::Client + Sync>(
    client: &C,
    addr: &Address,
) -> bool {
    tx::has_revealed_pk(client, addr).await
}

pub async fn submit_reveal_pk_aux<C: namada::ledger::queries::Client + Sync>(
    client: &C,
    ctx: &mut Context,
    public_key: &common::PublicKey,
    args: &args::Tx,
) -> Result<(), tx::Error> {
    let args = args::Tx {
        chain_id: args
            .clone()
            .chain_id
            .or_else(|| Some(ctx.config.ledger.chain_id.clone())),
        ..args.clone()
    };
    tx::submit_reveal_pk_aux::<C, _>(client, &mut ctx.wallet, public_key, &args)
        .await
}

/// Check if current epoch is in the last third of the voting period of the
/// proposal. This ensures that it is safe to optimize the vote writing to
/// storage.
async fn is_safe_voting_window<C: namada::ledger::queries::Client + Sync>(
    client: &C,
    proposal_id: u64,
    proposal_start_epoch: Epoch,
) -> Result<bool, tx::Error> {
    tx::is_safe_voting_window(client, proposal_id, proposal_start_epoch).await
}

/// Removes validators whose vote corresponds to that of the delegator (needless
/// vote)
async fn filter_delegations<C: namada::ledger::queries::Client + Sync>(
    client: &C,
    delegations: HashSet<Address>,
    proposal_id: u64,
    delegator_vote: &ProposalVote,
) -> HashSet<Address> {
    // Filter delegations by their validator's vote concurrently
    let delegations = futures::future::join_all(
        delegations
            .into_iter()
            // we cannot use `filter/filter_map` directly because we want to
            // return a future
            .map(|validator_address| async {
                let vote_key = gov_storage::get_vote_proposal_key(
                    proposal_id,
                    validator_address.to_owned(),
                    validator_address.to_owned(),
                );

                if let Some(validator_vote) =
                    rpc::query_storage_value::<C, ProposalVote>(
                        client, &vote_key,
                    )
                    .await
                {
                    if &validator_vote == delegator_vote {
                        return None;
                    }
                }
                Some(validator_address)
            }),
    )
    .await;
    // Take out the `None`s
    delegations.into_iter().flatten().collect()
}

pub async fn submit_bond<C: namada::ledger::queries::Client + Sync>(
    client: &C,
    ctx: &mut Context,
    mut args: args::Bond,
) -> Result<(), tx::Error> {
    args.tx.chain_id = args
        .tx
        .chain_id
        .or_else(|| Some(ctx.config.ledger.chain_id.clone()));
    tx::submit_bond::<C, _>(client, &mut ctx.wallet, args).await
}

pub async fn submit_unbond<C: namada::ledger::queries::Client + Sync>(
    client: &C,
    ctx: &mut Context,
    mut args: args::Unbond,
) -> Result<(), tx::Error> {
    args.tx.chain_id = args
        .tx
        .chain_id
        .or_else(|| Some(ctx.config.ledger.chain_id.clone()));
    tx::submit_unbond::<C, _>(client, &mut ctx.wallet, args).await
}

pub async fn submit_withdraw<C: namada::ledger::queries::Client + Sync>(
    client: &C,
    mut ctx: Context,
    mut args: args::Withdraw,
) -> Result<(), tx::Error> {
    args.tx.chain_id = args
        .tx
        .chain_id
        .or_else(|| Some(ctx.config.ledger.chain_id.clone()));
    tx::submit_withdraw::<C, _>(client, &mut ctx.wallet, args).await
}

pub async fn submit_validator_commission_change<
    C: namada::ledger::queries::Client + Sync,
>(
    client: &C,
    mut ctx: Context,
    mut args: args::TxCommissionRateChange,
) -> Result<(), tx::Error> {
    args.tx.chain_id = args
        .tx
        .chain_id
        .or_else(|| Some(ctx.config.ledger.chain_id.clone()));
    tx::submit_validator_commission_change::<C, _>(
        client,
        &mut ctx.wallet,
        args,
    )
    .await
}

/// Submit transaction and wait for result. Returns a list of addresses
/// initialized in the transaction if any. In dry run, this is always empty.
async fn process_tx<C: namada::ledger::queries::Client + Sync>(
    client: &C,
    mut ctx: Context,
    args: &args::Tx,
    tx: Tx,
    default_signer: TxSigningKey,
    #[cfg(not(feature = "mainnet"))] requires_pow: bool,
) -> Result<(Context, Vec<Address>), tx::Error> {
    let args = args::Tx {
        chain_id: args.clone().chain_id.or_else(|| Some(tx.chain_id.clone())),
        ..args.clone()
    };
    let res: Vec<Address> = tx::process_tx::<C, _>(
        client,
        &mut ctx.wallet,
        &args,
        tx,
        default_signer,
        #[cfg(not(feature = "mainnet"))]
        requires_pow,
    )
    .await?;
    Ok((ctx, res))
}

/// Save accounts initialized from a tx into the wallet, if any.
pub async fn save_initialized_accounts<U: WalletUtils>(
    wallet: &mut Wallet<U>,
    args: &args::Tx,
    initialized_accounts: Vec<Address>,
) {
    tx::save_initialized_accounts::<U>(wallet, args, initialized_accounts).await
}

/// Broadcast a transaction to be included in the blockchain and checks that
/// the tx has been successfully included into the mempool of a validator
///
/// In the case of errors in any of those stages, an error message is returned
pub async fn broadcast_tx<C: namada::ledger::queries::Client + Sync>(
    rpc_cli: &C,
    to_broadcast: &TxBroadcastData,
) -> Result<Response, tx::Error> {
    tx::broadcast_tx(rpc_cli, to_broadcast).await
}

/// Broadcast a transaction to be included in the blockchain.
///
/// Checks that
/// 1. The tx has been successfully included into the mempool of a validator
/// 2. The tx with encrypted payload has been included on the blockchain
/// 3. The decrypted payload of the tx has been included on the blockchain.
///
/// In the case of errors in any of those stages, an error message is returned
pub async fn submit_tx<C: namada::ledger::queries::Client + Sync>(
    client: &C,
    to_broadcast: TxBroadcastData,
) -> Result<TxResponse, tx::Error> {
    tx::submit_tx(client, to_broadcast).await
}
