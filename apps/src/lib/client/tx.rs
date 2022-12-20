use std::collections::HashSet;
use std::env;
use std::fmt::Debug;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::PathBuf;

use async_std::io::prelude::WriteExt;
use async_std::io::{self};
use borsh::{BorshDeserialize, BorshSerialize};
use masp_proofs::prover::LocalTxProver;
use namada::ledger::governance::storage as gov_storage;
use namada::ledger::masp::{ShieldedContext, ShieldedUtils};
use namada::ledger::rpc::{TxBroadcastData, TxResponse};
use namada::ledger::signing::TxSigningKey;
use namada::ledger::wallet::{Wallet, WalletUtils};
use namada::ledger::{masp, tx};
use namada::proto::Tx;
use namada::types::address::Address;
use namada::types::governance::{
    OfflineProposal, OfflineVote, Proposal, ProposalVote,
};
use namada::types::key::*;
use namada::types::storage::Epoch;
use namada::types::token;
use namada::types::transaction::governance::{
    InitProposalData, VoteProposalData,
};
use namada::types::transaction::InitValidator;
use namada::vm;
use rust_decimal::Decimal;

use super::rpc;
use crate::cli::context::WalletAddress;
use crate::cli::{args, safe_exit, Context};
use crate::client::signing::find_keypair;
use crate::facade::tendermint_rpc::endpoint::broadcast::tx_sync::Response;
use crate::facade::tendermint_rpc::{Client, HttpClient};
use crate::node::ledger::tendermint_node;
use crate::wallet::{gen_validator_keys, CliWalletUtils};

pub async fn submit_custom<
    C: Client + namada::ledger::queries::Client + Sync,
    U: WalletUtils,
>(
    client: &C,
    wallet: &mut Wallet<U>,
    args: args::TxCustom,
) -> Result<(), tx::Error> {
    tx::submit_custom::<C, U>(client, wallet, args).await
}

pub async fn submit_update_vp<
    C: Client + namada::ledger::queries::Client + Sync,
    U: WalletUtils,
>(
    client: &C,
    wallet: &mut Wallet<U>,
    args: args::TxUpdateVp,
) -> Result<(), tx::Error> {
    tx::submit_update_vp::<C, U>(client, wallet, args).await
}

pub async fn submit_init_account<
    C: Client + namada::ledger::queries::Client + Sync,
    U: WalletUtils,
>(
    client: &C,
    wallet: &mut Wallet<U>,
    args: args::TxInitAccount,
) -> Result<(), tx::Error> {
    tx::submit_init_account::<C, U>(client, wallet, args).await
}

pub async fn submit_init_validator<
    C: Client + namada::ledger::queries::Client + Sync,
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
        tx_code_path,
    }: args::TxInitValidator,
) {
    let alias = tx_args
        .initialized_account_alias
        .as_ref()
        .cloned()
        .unwrap_or_else(|| "validator".to_string());

    let validator_key_alias = format!("{}-key", alias);
    let consensus_key_alias = format!("{}-consensus-key", alias);
    let account_key = account_key.unwrap_or_else(|| {
        println!("Generating validator account key...");
        ctx.wallet
            .gen_key(
                scheme,
                Some(validator_key_alias.clone()),
                unsafe_dont_encrypt,
            )
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
            ctx.wallet
                .gen_key(
                    // Note that TM only allows ed25519 for consensus key
                    SchemeType::Ed25519,
                    Some(consensus_key_alias.clone()),
                    unsafe_dont_encrypt,
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

    crate::wallet::save(&ctx.wallet).unwrap_or_else(|err| eprintln!("{}", err));

    let validator_vp_code = validator_vp_code_path;

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
    // Validate the validator VP code
    if let Err(err) = vm::validate_untrusted_wasm(&validator_vp_code) {
        eprintln!(
            "Validator validity predicate code validation failed with {}",
            err
        );
        if !tx_args.force {
            safe_exit(1)
        }
    }
    let tx_code = tx_code_path;

    let data = InitValidator {
        account_key,
        consensus_key: consensus_key.ref_to(),
        protocol_key,
        dkg_key,
        commission_rate,
        max_commission_rate_change,
        validator_vp_code,
    };
    let data = data.try_to_vec().expect("Encoding tx data shouldn't fail");
    let tx = Tx::new(tx_code, Some(data));
    let initialized_accounts = process_tx::<C, CliWalletUtils>(
        client,
        &mut ctx.wallet,
        &tx_args,
        tx,
        TxSigningKey::WalletAddress(source),
    )
    .await
    .unwrap_or_else(|err| {
        eprintln!("Processing transaction failed with {}", err);
        safe_exit(1)
    });
    if !tx_args.dry_run {
        let (validator_address_alias, validator_address) =
            match &initialized_accounts[..] {
                // There should be 1 account for the validator itself
                [validator_address] => {
                    let validator_address_alias = match tx_args
                        .initialized_account_alias
                    {
                        Some(alias) => alias,
                        None => {
                            print!(
                                "Choose an alias for the validator address: "
                            );
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
                    eprintln!("Expected two accounts to be created");
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
    type C = HttpClient;

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

pub async fn submit_transfer<
    C: Client + namada::ledger::queries::Client + Sync,
    V: WalletUtils,
    U: ShieldedUtils<C = C>,
>(
    client: &C,
    wallet: &mut Wallet<V>,
    shielded: &mut ShieldedContext<U>,
    args: args::TxTransfer,
) -> Result<(), tx::Error> {
    tx::submit_transfer::<C, V, U>(client, wallet, shielded, args).await
}

pub async fn submit_ibc_transfer<
    C: Client + namada::ledger::queries::Client + Sync,
    U: WalletUtils,
>(
    client: &C,
    wallet: &mut Wallet<U>,
    args: args::TxIbcTransfer,
) -> Result<(), tx::Error> {
    tx::submit_ibc_transfer::<C, U>(client, wallet, args).await
}

pub async fn submit_init_proposal<
    C: Client + namada::ledger::queries::Client + Sync,
>(
    client: &C,
    mut ctx: Context,
    args: args::InitProposal,
) -> Result<(), tx::Error> {
    let file = File::open(&args.proposal_data).expect("File must exist.");
    let proposal: Proposal =
        serde_json::from_reader(file).expect("JSON was not well-formatted");

    let signer = WalletAddress::new(proposal.clone().author.to_string());
    let governance_parameters = rpc::get_governance_parameters(client).await;
    let current_epoch = rpc::query_epoch(client).await;

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
        let tx_code = args.tx_code_path;
        let tx = Tx::new(tx_code, Some(data));

        process_tx::<C, CliWalletUtils>(
            client,
            &mut ctx.wallet,
            &args.tx,
            tx,
            TxSigningKey::WalletAddress(signer),
        )
        .await?;
        Ok(())
    }
}

pub async fn submit_vote_proposal<
    C: Client + namada::ledger::queries::Client + Sync,
    U: WalletUtils,
>(
    client: &C,
    wallet: &mut Wallet<U>,
    args: args::VoteProposal,
) -> Result<(), tx::Error> {
    let signer = if let Some(addr) = &args.tx.signer {
        addr
    } else {
        eprintln!("Missing mandatory argument --signer.");
        safe_exit(1)
    };

    if args.offline {
        let signer = signer;
        let proposal_file_path = args
            .proposal_data
            .ok_or(tx::Error::Other(format!("Proposal file should exist.")))?;
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

        let signing_key = find_keypair::<C, U>(client, wallet, &signer).await?;
        let offline_vote = OfflineVote::new(
            &proposal,
            args.vote,
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
        let current_epoch = rpc::query_epoch(client).await;

        let voter_address = signer.clone();
        let proposal_id = args.proposal_id.unwrap();
        let proposal_start_epoch_key =
            gov_storage::get_voting_start_epoch_key(proposal_id);
        let proposal_start_epoch = rpc::query_storage_value::<C, Epoch>(
            &client,
            &proposal_start_epoch_key,
        )
        .await;

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
                        &args.vote,
                    )
                    .await;
                }

                let tx_data = VoteProposalData {
                    id: proposal_id,
                    vote: args.vote,
                    voter: voter_address,
                    delegations: delegations.into_iter().collect(),
                };

                let data = tx_data
                    .try_to_vec()
                    .expect("Encoding proposal data shouldn't fail");
                let tx_code = args.tx_code_path;
                let tx = Tx::new(tx_code, Some(data));

                process_tx::<C, U>(
                    client,
                    wallet,
                    &args.tx,
                    tx,
                    TxSigningKey::WalletAddress(signer.clone()),
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

pub async fn submit_reveal_pk<
    C: Client + namada::ledger::queries::Client + Sync,
    U: WalletUtils,
>(
    client: &C,
    wallet: &mut Wallet<U>,
    args: args::RevealPk,
) -> Result<(), tx::Error> {
    tx::submit_reveal_pk::<C, U>(client, wallet, args).await
}

pub async fn reveal_pk_if_needed<
    C: Client + namada::ledger::queries::Client + Sync,
    U: WalletUtils,
>(
    client: &C,
    wallet: &mut Wallet<U>,
    public_key: &common::PublicKey,
    args: &args::Tx,
) -> Result<bool, tx::Error> {
    tx::reveal_pk_if_needed::<C, U>(client, wallet, public_key, args).await
}

pub async fn has_revealed_pk<
    C: Client + namada::ledger::queries::Client + Sync,
>(
    client: &C,
    addr: &Address,
) -> bool {
    tx::has_revealed_pk(client, addr).await
}

pub async fn submit_reveal_pk_aux<
    C: Client + namada::ledger::queries::Client + Sync,
    U: WalletUtils,
>(
    client: &C,
    wallet: &mut Wallet<U>,
    public_key: &common::PublicKey,
    args: &args::Tx,
) -> Result<(), tx::Error> {
    tx::submit_reveal_pk_aux::<C, U>(client, wallet, public_key, args).await
}

/// Check if current epoch is in the last third of the voting period of the
/// proposal. This ensures that it is safe to optimize the vote writing to
/// storage.
async fn is_safe_voting_window<
    C: Client + namada::ledger::queries::Client + Sync,
>(
    client: &C,
    proposal_id: u64,
    proposal_start_epoch: Epoch,
) -> Result<bool, tx::Error> {
    tx::is_safe_voting_window(client, proposal_id, proposal_start_epoch).await
}

/// Removes validators whose vote corresponds to that of the delegator (needless
/// vote)
async fn filter_delegations<
    C: Client + namada::ledger::queries::Client + Sync,
>(
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

pub async fn submit_bond<
    C: Client + namada::ledger::queries::Client + Sync,
    U: WalletUtils,
>(
    client: &C,
    wallet: &mut Wallet<U>,
    args: args::Bond,
) -> Result<(), tx::Error> {
    tx::submit_bond::<C, U>(client, wallet, args).await
}

pub async fn submit_unbond<
    C: Client + namada::ledger::queries::Client + Sync,
    U: WalletUtils,
>(
    client: &C,
    wallet: &mut Wallet<U>,
    args: args::Unbond,
) -> Result<(), tx::Error> {
    tx::submit_unbond::<C, U>(client, wallet, args).await
}

pub async fn submit_withdraw<
    C: Client + namada::ledger::queries::Client + Sync,
    U: WalletUtils,
>(
    client: &C,
    wallet: &mut Wallet<U>,
    args: args::Withdraw,
) -> Result<(), tx::Error> {
    tx::submit_withdraw::<C, U>(client, wallet, args).await
}

pub async fn submit_validator_commission_change<
    C: Client + namada::ledger::queries::Client + Sync,
    U: WalletUtils,
>(
    client: &C,
    wallet: &mut Wallet<U>,
    args: args::TxCommissionRateChange,
) -> Result<(), tx::Error> {
    tx::submit_validator_commission_change::<C, U>(client, wallet, args).await
}

/// Submit transaction and wait for result. Returns a list of addresses
/// initialized in the transaction if any. In dry run, this is always empty.
async fn process_tx<
    C: Client + namada::ledger::queries::Client + Sync,
    U: WalletUtils,
>(
    client: &C,
    wallet: &mut Wallet<U>,
    args: &args::Tx,
    tx: Tx,
    default_signer: TxSigningKey,
) -> Result<Vec<Address>, tx::Error> {
    tx::process_tx::<C, U>(client, wallet, args, tx, default_signer).await
}

/// Save accounts initialized from a tx into the wallet, if any.
async fn save_initialized_accounts<U: WalletUtils>(
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
pub async fn broadcast_tx<C: Client + Sync>(
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
pub async fn submit_tx<C: Client + namada::ledger::queries::Client + Sync>(
    client: &C,
    to_broadcast: TxBroadcastData,
) -> Result<TxResponse, tx::Error> {
    tx::submit_tx(client, to_broadcast).await
}
