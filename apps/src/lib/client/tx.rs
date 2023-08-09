use std::collections::HashSet;
use std::env;
use std::fmt::Debug;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::PathBuf;

use async_trait::async_trait;
use borsh::{BorshDeserialize, BorshSerialize};
use data_encoding::HEXLOWER_PERMISSIVE;
use masp_proofs::prover::LocalTxProver;
use namada::ledger::governance::storage as gov_storage;
use namada::ledger::queries::Client;
use namada::ledger::rpc::{TxBroadcastData, TxResponse};
use namada::ledger::signing::find_pk;
use namada::ledger::wallet::{Wallet, WalletUtils};
use namada::ledger::{masp, pos, signing, tx};
use namada::proof_of_stake::parameters::PosParams;
use namada::proto::Tx;
use namada::types::address::{Address, ImplicitAddress};
use namada::types::dec::Dec;
use namada::types::governance::{
    OfflineProposal, OfflineVote, Proposal, ProposalVote, VoteType,
};
use namada::types::key::{self, *};
use namada::types::storage::{Epoch, Key};
use namada::types::token;
use namada::types::transaction::governance::{ProposalType, VoteProposalData};
use namada::types::transaction::pos::InitValidator;

use super::rpc;
use crate::cli::context::WalletAddress;
use crate::cli::{args, safe_exit, Context};
use crate::client::rpc::query_wasm_code_hash;
use crate::client::tx::tx::ProcessTxResponse;
use crate::config::TendermintMode;
use crate::facade::tendermint_rpc::endpoint::broadcast::tx_sync::Response;
use crate::node::ledger::tendermint_node;
use crate::wallet::{gen_validator_keys, read_and_confirm_encryption_password};

// Build a transaction to reveal the signer of the given transaction.
pub async fn submit_reveal_aux<C: namada::ledger::queries::Client + Sync>(
    client: &C,
    ctx: &mut Context,
    args: args::Tx,
    address: &Address,
) -> Result<(), tx::Error> {
    if args.dump_tx {
        return Ok(());
    }

    if let Address::Implicit(ImplicitAddress(pkh)) = address {
        let key = ctx
            .wallet
            .find_key_by_pkh(pkh, args.clone().password)
            .map_err(|e| tx::Error::Other(e.to_string()))?;
        let public_key = key.ref_to();

        if tx::is_reveal_pk_needed::<C>(client, address, args.force).await? {
            let signing_data = signing::aux_signing_data(
                client,
                &mut ctx.wallet,
                &args,
                &None,
                None,
            )
            .await?;

            let mut tx = tx::build_reveal_pk::<C>(
                client,
                &args,
                address,
                &public_key,
                &signing_data.gas_payer,
            )
            .await?;

            signing::generate_test_vector(client, &mut ctx.wallet, &tx).await;

            signing::sign_tx(&mut ctx.wallet, &args, &mut tx, signing_data);

            tx::process_tx(client, &mut ctx.wallet, &args, tx).await?;
        }
    }

    Ok(())
}

pub async fn submit_custom<C>(
    client: &C,
    ctx: &mut Context,
    args: args::TxCustom,
) -> Result<(), tx::Error>
where
    C: namada::ledger::queries::Client + Sync,
    C::Error: std::fmt::Display,
{
    let default_signer = Some(args.owner.clone());
    let signing_data = signing::aux_signing_data(
        client,
        &mut ctx.wallet,
        &args.tx,
        &Some(args.owner.clone()),
        default_signer,
    )
    .await?;

    submit_reveal_aux(client, ctx, args.tx.clone(), &args.owner).await?;

    let mut tx =
        tx::build_custom(client, args.clone(), &signing_data.gas_payer).await?;

    signing::generate_test_vector(client, &mut ctx.wallet, &tx).await;

    if args.tx.dump_tx {
        tx::dump_tx(&args.tx, tx);
    } else {
        signing::sign_tx(&mut ctx.wallet, &args.tx, &mut tx, signing_data);
        tx::process_tx(client, &mut ctx.wallet, &args.tx, tx).await?;
    }

    Ok(())
}

pub async fn submit_update_account<C>(
    client: &C,
    ctx: &mut Context,
    args: args::TxUpdateAccount,
) -> Result<(), tx::Error>
where
    C: namada::ledger::queries::Client + Sync,
    C::Error: std::fmt::Display,
{
    let default_signer = Some(args.addr.clone());
    let signing_data = signing::aux_signing_data(
        client,
        &mut ctx.wallet,
        &args.tx,
        &Some(args.addr.clone()),
        default_signer,
    )
    .await?;

    let mut tx =
        tx::build_update_account(client, args.clone(), &signing_data.gas_payer)
            .await?;

    signing::generate_test_vector(client, &mut ctx.wallet, &tx).await;

    if args.tx.dump_tx {
        tx::dump_tx(&args.tx, tx);
    } else {
        signing::sign_tx(&mut ctx.wallet, &args.tx, &mut tx, signing_data);
        tx::process_tx(client, &mut ctx.wallet, &args.tx, tx).await?;
    }

    Ok(())
}

pub async fn submit_init_account<C>(
    client: &C,
    ctx: &mut Context,
    args: args::TxInitAccount,
) -> Result<(), tx::Error>
where
    C: namada::ledger::queries::Client + Sync,
    C::Error: std::fmt::Display,
{
    let signing_data = signing::aux_signing_data(
        client,
        &mut ctx.wallet,
        &args.tx,
        &None,
        None,
    )
    .await?;

    let mut tx =
        tx::build_init_account(client, args.clone(), &signing_data.gas_payer)
            .await?;

    signing::generate_test_vector(client, &mut ctx.wallet, &tx).await;

    if args.tx.dump_tx {
        tx::dump_tx(&args.tx, tx);
    } else {
        signing::sign_tx(&mut ctx.wallet, &args.tx, &mut tx, signing_data);
        tx::process_tx(client, &mut ctx.wallet, &args.tx, tx).await?;
    }

    Ok(())
}

pub async fn submit_init_validator<C>(
    client: &C,
    mut ctx: Context,
    args::TxInitValidator {
        tx: tx_args,
        scheme,
        account_keys,
        threshold,
        consensus_key,
        eth_cold_key,
        eth_hot_key,
        protocol_key,
        commission_rate,
        max_commission_rate_change,
        validator_vp_code_path,
        unsafe_dont_encrypt,
        tx_code_path: _,
    }: args::TxInitValidator,
) -> Result<(), tx::Error>
where
    C: namada::ledger::queries::Client + Sync,
    C::Error: std::fmt::Display,
{
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

    let threshold = match threshold {
        Some(threshold) => threshold,
        None => {
            if account_keys.len() == 1 {
                1u8
            } else {
                safe_exit(1)
            }
        }
    };
    let eth_hot_key_alias = format!("{}-eth-hot-key", alias);
    let eth_cold_key_alias = format!("{}-eth-cold-key", alias);

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
            let password =
                read_and_confirm_encryption_password(unsafe_dont_encrypt);
            ctx.wallet
                .gen_key(
                    // Note that TM only allows ed25519 for consensus key
                    SchemeType::Ed25519,
                    Some(consensus_key_alias.clone()),
                    tx_args.wallet_alias_force,
                    password,
                    None,
                )
                .expect("Key generation should not fail.")
                .expect("No existing alias expected.")
                .1
        });

    let eth_cold_pk = eth_cold_key
        .map(|key| match key {
            common::SecretKey::Secp256k1(_) => key.ref_to(),
            common::SecretKey::Ed25519(_) => {
                eprintln!("Eth cold key can only be secp256k1");
                safe_exit(1)
            }
        })
        .unwrap_or_else(|| {
            println!("Generating Eth cold key...");
            let password =
                read_and_confirm_encryption_password(unsafe_dont_encrypt);
            ctx.wallet
                .gen_key(
                    // Note that ETH only allows secp256k1
                    SchemeType::Secp256k1,
                    Some(eth_cold_key_alias.clone()),
                    tx_args.wallet_alias_force,
                    password,
                    None,
                )
                .expect("Key generation should not fail.")
                .expect("No existing alias expected.")
                .1
                .ref_to()
        });

    let eth_hot_pk = eth_hot_key
        .map(|key| match key {
            common::SecretKey::Secp256k1(_) => key.ref_to(),
            common::SecretKey::Ed25519(_) => {
                eprintln!("Eth hot key can only be secp256k1");
                safe_exit(1)
            }
        })
        .unwrap_or_else(|| {
            println!("Generating Eth hot key...");
            let password =
                read_and_confirm_encryption_password(unsafe_dont_encrypt);
            ctx.wallet
                .gen_key(
                    // Note that ETH only allows secp256k1
                    SchemeType::Secp256k1,
                    Some(eth_hot_key_alias.clone()),
                    tx_args.wallet_alias_force,
                    password,
                    None,
                )
                .expect("Key generation should not fail.")
                .expect("No existing alias expected.")
                .1
                .ref_to()
        });

    if protocol_key.is_none() {
        println!("Generating protocol signing key...");
    }
    // Generate the validator keys
    let validator_keys = gen_validator_keys(
        &mut ctx.wallet,
        Some(eth_hot_pk.clone()),
        protocol_key,
        scheme,
    )
    .unwrap();
    let protocol_key = validator_keys.get_protocol_keypair().ref_to();
    let dkg_key = validator_keys
        .dkg_keypair
        .as_ref()
        .expect("DKG sessions keys should have been created")
        .public();

    let validator_vp_code_hash = query_wasm_code_hash::<C>(
        client,
        validator_vp_code_path.to_str().unwrap(),
    )
    .await
    .unwrap();

    // Validate the commission rate data
    if commission_rate > Dec::one() || commission_rate < Dec::zero() {
        eprintln!(
            "The validator commission rate must not exceed 1.0 or 100%, and \
             it must be 0 or positive"
        );
        if !tx_args.force {
            safe_exit(1)
        }
    }
    if max_commission_rate_change > Dec::one()
        || max_commission_rate_change < Dec::zero()
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

    let chain_id = tx_args.chain_id.clone().unwrap();
    let mut tx = Tx::new(chain_id, tx_args.expiration);
    let extra_section_hash =
        tx.add_extra_section_from_hash(validator_vp_code_hash);

    let data = InitValidator {
        account_keys,
        threshold,
        consensus_key: consensus_key.ref_to(),
        eth_cold_key: key::secp256k1::PublicKey::try_from_pk(&eth_cold_pk)
            .unwrap(),
        eth_hot_key: key::secp256k1::PublicKey::try_from_pk(&eth_hot_pk)
            .unwrap(),
        protocol_key,
        dkg_key,
        commission_rate,
        max_commission_rate_change,
        validator_vp_code_hash: extra_section_hash,
    };

    tx.add_code_from_hash(tx_code_hash).add_data(data);

    let signing_data = signing::aux_signing_data(
        client,
        &mut ctx.wallet,
        &tx_args,
        &None,
        None,
    )
    .await?;

    tx::prepare_tx(
        client,
        &tx_args,
        &mut tx,
        signing_data.gas_payer.clone(),
        #[cfg(not(feature = "mainnet"))]
        false,
    )
    .await;

    signing::generate_test_vector(client, &mut ctx.wallet, &tx).await;

    if tx_args.dump_tx {
        tx::dump_tx(&tx_args, tx);
    } else {
        signing::sign_tx(&mut ctx.wallet, &tx_args, &mut tx, signing_data);

        let result = tx::process_tx(client, &mut ctx.wallet, &tx_args, tx)
            .await?
            .initialized_accounts();

        if !tx_args.dry_run {
            let (validator_address_alias, validator_address) = match &result[..]
            {
                // There should be 1 account for the validator itself
                [validator_address] => {
                    if let Some(alias) =
                        ctx.wallet.find_alias(validator_address)
                    {
                        (alias.clone(), validator_address.clone())
                    } else {
                        eprintln!("Expected one account to be created");
                        safe_exit(1)
                    }
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

            let tendermint_home = ctx.config.ledger.cometbft_dir();
            tendermint_node::write_validator_key(
                &tendermint_home,
                &consensus_key,
            );
            tendermint_node::write_validator_state(tendermint_home);

            // Write Namada config stuff or figure out how to do the above
            // tendermint_node things two epochs in the future!!!
            ctx.config.ledger.shell.tendermint_mode = TendermintMode::Validator;
            ctx.config
                .write(
                    &ctx.config.ledger.shell.base_dir,
                    &ctx.config.ledger.chain_id,
                    true,
                )
                .unwrap();

            let key = pos::params_key();
            let pos_params =
                rpc::query_storage_value::<C, PosParams>(client, &key)
                    .await
                    .expect("Pos parameter should be defined.");

            println!();
            println!(
                "The validator's addresses and keys were stored in the wallet:"
            );
            println!("  Validator address \"{}\"", validator_address_alias);
            println!("  Validator account key \"{}\"", validator_key_alias);
            println!("  Consensus key \"{}\"", consensus_key_alias);
            println!(
                "The ledger node has been setup to use this validator's \
                 address and consensus key."
            );
            println!(
                "Your validator will be active in {} epochs. Be sure to \
                 restart your node for the changes to take effect!",
                pos_params.pipeline_len
            );
        } else {
            println!("Transaction dry run. No addresses have been saved.");
        }
    }
    Ok(())
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
            masp_proofs::download_masp_parameters(None)
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

#[async_trait(?Send)]
impl masp::ShieldedUtils for CLIShieldedUtils {
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
    async fn load(self) -> std::io::Result<masp::ShieldedContext<Self>> {
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
    async fn save(
        &self,
        ctx: &masp::ShieldedContext<Self>,
    ) -> std::io::Result<()> {
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

pub async fn submit_transfer<C: Client + Sync>(
    client: &C,
    mut ctx: Context,
    args: args::TxTransfer,
) -> Result<(), tx::Error> {
    for _ in 0..2 {
        let default_signer = Some(args.source.effective_address());
        let signing_data = signing::aux_signing_data(
            client,
            &mut ctx.wallet,
            &args.tx,
            &Some(args.source.effective_address()),
            default_signer,
        )
        .await?;

        submit_reveal_aux(
            client,
            &mut ctx,
            args.tx.clone(),
            &args.source.effective_address(),
        )
        .await?;

        let arg = args.clone();
        let (mut tx, tx_epoch) = tx::build_transfer(
            client,
            &mut ctx.shielded,
            arg,
            &signing_data.gas_payer,
        )
        .await?;
        signing::generate_test_vector(client, &mut ctx.wallet, &tx).await;

        if args.tx.dump_tx {
            tx::dump_tx(&args.tx, tx);
        } else {
            signing::sign_tx(&mut ctx.wallet, &args.tx, &mut tx, signing_data);
            let result =
                tx::process_tx(client, &mut ctx.wallet, &args.tx, tx).await?;

            let submission_epoch = rpc::query_and_print_epoch(client).await;

            match result {
                ProcessTxResponse::Applied(resp) if
                // If a transaction is shielded
                    tx_epoch.is_some() &&
                // And it is rejected by a VP
                    resp.code == 1.to_string() &&
                // And its submission epoch doesn't match construction epoch
                    tx_epoch.unwrap() != submission_epoch =>
                {
                    // Then we probably straddled an epoch boundary. Let's retry...
                    eprintln!(
                        "MASP transaction rejected and this may be due to the \
                        epoch changing. Attempting to resubmit transaction.",
                    );
                    continue;
                },
                // Otherwise either the transaction was successful or it will not
                // benefit from resubmission
                _ => break,
            }
        }
    }

    Ok(())
}

pub async fn submit_ibc_transfer<C>(
    client: &C,
    mut ctx: Context,
    args: args::TxIbcTransfer,
) -> Result<(), tx::Error>
where
    C: namada::ledger::queries::Client + Sync,
    C::Error: std::fmt::Display,
{
    let default_signer = Some(args.source.clone());
    let signing_data = signing::aux_signing_data(
        client,
        &mut ctx.wallet,
        &args.tx,
        &Some(args.source.clone()),
        default_signer,
    )
    .await?;

    submit_reveal_aux(client, &mut ctx, args.tx.clone(), &args.source).await?;

    let mut tx =
        tx::build_ibc_transfer(client, args.clone(), &signing_data.gas_payer)
            .await?;
    signing::generate_test_vector(client, &mut ctx.wallet, &tx).await;

    if args.tx.dump_tx {
        tx::dump_tx(&args.tx, tx);
    } else {
        signing::sign_tx(&mut ctx.wallet, &args.tx, &mut tx, signing_data);
        tx::process_tx(client, &mut ctx.wallet, &args.tx, tx).await?;
    }

    Ok(())
}

pub async fn submit_init_proposal<C>(
    client: &C,
    mut ctx: Context,
    args: args::InitProposal,
) -> Result<(), tx::Error>
where
    C: namada::ledger::queries::Client + Sync,
    C::Error: std::fmt::Display,
{
    let file = File::open(&args.proposal_data).expect("File must exist.");
    let proposal: Proposal =
        serde_json::from_reader(file).expect("JSON was not well-formatted");

    let signer = WalletAddress::new(proposal.clone().author.to_string());
    let current_epoch = rpc::query_and_print_epoch(client).await;

    let governance_parameters = rpc::get_governance_parameters(client).await;
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
        let key = find_pk(client, &mut ctx.wallet, &signer, None).await?;
        let signing_key =
            signing::find_key_by_pk(&mut ctx.wallet, &args.tx, &key)?;
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
        let tx_data = proposal.clone().try_into();
        let (mut init_proposal_data, init_proposal_content, init_proposal_code) =
            if let Ok(data) = tx_data {
                data
            } else {
                eprintln!("Invalid data for init proposal transaction.");
                safe_exit(1)
            };

        let balance =
            rpc::get_token_balance(client, &ctx.native_token, &proposal.author)
                .await;
        if balance
            < token::Amount::from_uint(
                governance_parameters.min_proposal_fund,
                0,
            )
            .unwrap()
        {
            eprintln!(
                "Address {} doesn't have enough funds.",
                &proposal.author
            );
            safe_exit(1);
        }

        if init_proposal_content.len()
            > governance_parameters.max_proposal_content_size as usize
        {
            eprintln!("Proposal content size too big.",);
            safe_exit(1);
        }

        let tx_code_hash = query_wasm_code_hash(client, args::TX_INIT_PROPOSAL)
            .await
            .unwrap();

        let default_signer = Some(signer.clone());
        let signing_data = signing::aux_signing_data(
            client,
            &mut ctx.wallet,
            &args.tx,
            &Some(signer.clone()),
            default_signer,
        )
        .await?;

        let chain_id = args.tx.chain_id.clone().unwrap();
        let mut tx = Tx::new(chain_id, args.tx.expiration);

        // Put any proposal content into an extra section
        let extra_section_hash = tx.add_extra_section(init_proposal_content).1;
        init_proposal_data.content = extra_section_hash;

        // Put any proposal code into an extra section
        if let Some(init_proposal_code) = init_proposal_code {
            let extra_section_hash = tx.add_extra_section(init_proposal_code).1;
            init_proposal_data.r#type =
                ProposalType::Default(Some(extra_section_hash));
        }

        tx.add_code_from_hash(tx_code_hash)
            .add_data(init_proposal_data);

        submit_reveal_aux(client, &mut ctx, args.tx.clone(), &signer).await?;

        tx::prepare_tx(
            client,
            &args.tx,
            &mut tx,
            signing_data.gas_payer.clone(),
            #[cfg(not(feature = "mainnet"))]
            false,
        )
        .await;
        signing::generate_test_vector(client, &mut ctx.wallet, &tx).await;

        if args.tx.dump_tx {
            tx::dump_tx(&args.tx, tx);
        } else {
            signing::sign_tx(&mut ctx.wallet, &args.tx, &mut tx, signing_data);
            tx::process_tx(client, &mut ctx.wallet, &args.tx, tx).await?;
        }

        Ok(())
    }
}

pub async fn submit_vote_proposal<C>(
    client: &C,
    mut ctx: Context,
    args: args::VoteProposal,
) -> Result<(), tx::Error>
where
    C: namada::ledger::queries::Client + Sync,
    C::Error: std::fmt::Display,
{
    // Construct vote
    let proposal_vote = match args.vote.to_ascii_lowercase().as_str() {
        "yay" => {
            if let Some(pgf) = args.proposal_pgf {
                let splits = pgf.trim().split_ascii_whitespace();
                let address_iter = splits.clone().step_by(2);
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
                    set.insert((
                        address,
                        token::Amount::from_uint(cap, 0).unwrap(),
                    ));
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
        let public_key = namada::ledger::rpc::get_public_key_at(
            client,
            &proposal.address,
            0,
        )
        .await
        .expect("Public key should exist.");
        if !proposal.check_signature(&public_key) {
            eprintln!("Proposal signature mismatch!");
            safe_exit(1)
        }

        let key =
            find_pk(client, &mut ctx.wallet, &args.voter_address, None).await?;
        let signing_key =
            signing::find_key_by_pk(&mut ctx.wallet, &args.tx, &key)?;
        let offline_vote = OfflineVote::new(
            &proposal,
            proposal_vote,
            args.voter_address.clone(),
            &signing_key,
        );

        let proposal_vote_filename = proposal_file_path
            .parent()
            .expect("No parent found")
            .join(format!("proposal-vote-{}", &args.voter_address.to_string()));
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

        let voter_address = args.voter_address.clone();
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

                let tx_code_hash = query_wasm_code_hash(
                    client,
                    args.tx_code_path.to_str().unwrap(),
                )
                .await
                .unwrap();

                let default_signer = Some(args.voter_address.clone());
                let signing_data = signing::aux_signing_data(
                    client,
                    &mut ctx.wallet,
                    &args.tx,
                    &Some(args.voter_address.clone()),
                    default_signer,
                )
                .await?;

                let chain_id = args.tx.chain_id.clone().unwrap();
                let mut tx = Tx::new(chain_id, args.tx.expiration);
                tx.add_code_from_hash(tx_code_hash).add_data(tx_data);

                tx::prepare_tx(
                    client,
                    &args.tx,
                    &mut tx,
                    signing_data.gas_payer.clone(),
                    #[cfg(not(feature = "mainnet"))]
                    false,
                )
                .await;
                signing::generate_test_vector(client, &mut ctx.wallet, &tx)
                    .await;

                if args.tx.dump_tx {
                    tx::dump_tx(&args.tx, tx);
                } else {
                    // no need to releal pk since people who an vote on
                    // governane proposal must be enstablished addresses

                    signing::sign_tx(
                        &mut ctx.wallet,
                        &args.tx,
                        &mut tx,
                        signing_data,
                    );
                    tx::process_tx(client, &mut ctx.wallet, &args.tx, tx)
                        .await?;
                }
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

pub async fn sign_tx<C>(
    client: &C,
    ctx: &mut Context,
    args::SignTx {
        tx: tx_args,
        tx_data,
        owner,
    }: args::SignTx,
) -> Result<(), tx::Error>
where
    C: namada::ledger::queries::Client + Sync,
    C::Error: std::fmt::Display,
{
    let tx = if let Ok(transaction) = Tx::deserialize(tx_data.as_ref()) {
        transaction
    } else {
        eprintln!("Couldn't decode the transaction.");
        safe_exit(1)
    };

    let default_signer = Some(owner.clone());
    let signing_data = signing::aux_signing_data(
        client,
        &mut ctx.wallet,
        &tx_args,
        &Some(owner),
        default_signer,
    )
    .await?;

    let secret_keys = &signing_data
        .public_keys
        .iter()
        .filter_map(|public_key| {
            if let Ok(secret_key) =
                signing::find_key_by_pk(&mut ctx.wallet, &tx_args, public_key)
            {
                Some(secret_key)
            } else {
                eprintln!(
                    "Couldn't find the secret key for {}. Skipping signature \
                     generation.",
                    public_key
                );
                None
            }
        })
        .collect::<Vec<common::SecretKey>>();

    if let Some(account_public_keys_map) = signing_data.account_public_keys_map {
        let signatures = tx.compute_section_signature(
            secret_keys,
            &account_public_keys_map,
        );

        for signature in &signatures {
            let filename = format!(
                "offline_signature_{}_{}.tx",
                tx.header_hash(),
                signature.index
            );
            let output_path = match &tx_args.output_folder {
                Some(path) => path.join(filename),
                None => filename.into(),
            };

            let signature_path = File::create(&output_path)
                .expect("Should be able to create signature file.");

            serde_json::to_writer_pretty(signature_path, &signature.serialize())
                .expect("Signature should be deserializable.");
            println!(
                "Signature for {} serialized at {}",
                &account_public_keys_map
                    .get_public_key_from_index(signature.index)
                    .unwrap(),
                output_path.display()
            );
        }
    }
    Ok(())
}

pub async fn submit_reveal_pk<C>(
    client: &C,
    ctx: &mut Context,
    args: args::RevealPk,
) -> Result<(), tx::Error>
where
    C: namada::ledger::queries::Client + Sync,
    C::Error: std::fmt::Display,
{
    submit_reveal_aux(client, ctx, args.tx, &(&args.public_key).into()).await?;

    Ok(())
}

/// Check if current epoch is in the last third of the voting period of the
/// proposal. This ensures that it is safe to optimize the vote writing to
/// storage.
async fn is_safe_voting_window<C>(
    client: &C,
    proposal_id: u64,
    proposal_start_epoch: Epoch,
) -> Result<bool, tx::Error>
where
    C: namada::ledger::queries::Client + Sync,
    C::Error: std::fmt::Display,
{
    tx::is_safe_voting_window(client, proposal_id, proposal_start_epoch).await
}

/// Removes validators whose vote corresponds to that of the delegator (needless
/// vote)
async fn filter_delegations<C>(
    client: &C,
    delegations: HashSet<Address>,
    proposal_id: u64,
    delegator_vote: &ProposalVote,
) -> HashSet<Address>
where
    C: namada::ledger::queries::Client + Sync,
    C::Error: std::fmt::Display,
{
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

pub async fn submit_bond<C>(
    client: &C,
    ctx: &mut Context,
    args: args::Bond,
) -> Result<(), tx::Error>
where
    C: namada::ledger::queries::Client + Sync,
    C::Error: std::fmt::Display,
{
    let default_address = args.source.clone().unwrap_or(args.validator.clone());
    let default_signer = Some(default_address.clone());
    let signing_data = signing::aux_signing_data(
        client,
        &mut ctx.wallet,
        &args.tx,
        &Some(default_address.clone()),
        default_signer,
    )
    .await?;

    submit_reveal_aux(client, ctx, args.tx.clone(), &default_address).await?;

    let mut tx =
        tx::build_bond::<C>(client, args.clone(), &signing_data.gas_payer)
            .await?;
    signing::generate_test_vector(client, &mut ctx.wallet, &tx).await;

    if args.tx.dump_tx {
        tx::dump_tx(&args.tx, tx);
    } else {
        signing::sign_tx(&mut ctx.wallet, &args.tx, &mut tx, signing_data);

        tx::process_tx(client, &mut ctx.wallet, &args.tx, tx).await?;
    }

    Ok(())
}

pub async fn submit_unbond<C>(
    client: &C,
    ctx: &mut Context,
    args: args::Unbond,
) -> Result<(), tx::Error>
where
    C: namada::ledger::queries::Client + Sync,
    C::Error: std::fmt::Display,
{
    let default_address = args.source.clone().unwrap_or(args.validator.clone());
    let default_signer = Some(default_address.clone());
    let signing_data = signing::aux_signing_data(
        client,
        &mut ctx.wallet,
        &args.tx,
        &Some(default_address),
        default_signer,
    )
    .await?;

    let (mut tx, latest_withdrawal_pre) = tx::build_unbond(
        client,
        &mut ctx.wallet,
        args.clone(),
        &signing_data.gas_payer,
    )
    .await?;
    signing::generate_test_vector(client, &mut ctx.wallet, &tx).await;

    if args.tx.dump_tx {
        tx::dump_tx(&args.tx, tx);
    } else {
        signing::sign_tx(&mut ctx.wallet, &args.tx, &mut tx, signing_data);

        tx::process_tx(client, &mut ctx.wallet, &args.tx, tx).await?;

        tx::query_unbonds(client, args.clone(), latest_withdrawal_pre).await?;
    }

    Ok(())
}

pub async fn submit_withdraw<C>(
    client: &C,
    mut ctx: Context,
    args: args::Withdraw,
) -> Result<(), tx::Error>
where
    C: namada::ledger::queries::Client + Sync,
    C::Error: std::fmt::Display,
{
    let default_address = args.source.clone().unwrap_or(args.validator.clone());
    let default_signer = Some(default_address.clone());
    let signing_data = signing::aux_signing_data(
        client,
        &mut ctx.wallet,
        &args.tx,
        &Some(default_address),
        default_signer,
    )
    .await?;

    let mut tx =
        tx::build_withdraw(client, args.clone(), &signing_data.gas_payer)
            .await?;
    signing::generate_test_vector(client, &mut ctx.wallet, &tx).await;

    if args.tx.dump_tx {
        tx::dump_tx(&args.tx, tx);
    } else {
        signing::sign_tx(&mut ctx.wallet, &args.tx, &mut tx, signing_data);

        tx::process_tx(client, &mut ctx.wallet, &args.tx, tx).await?;
    }

    Ok(())
}

pub async fn submit_validator_commission_change<C>(
    client: &C,
    mut ctx: Context,
    args: args::CommissionRateChange,
) -> Result<(), tx::Error>
where
    C: namada::ledger::queries::Client + Sync,
    C::Error: std::fmt::Display,
{
    let default_signer = Some(args.validator.clone());
    let signing_data = signing::aux_signing_data(
        client,
        &mut ctx.wallet,
        &args.tx,
        &Some(args.validator.clone()),
        default_signer,
    )
    .await?;

    let mut tx = tx::build_validator_commission_change(
        client,
        args.clone(),
        &signing_data.gas_payer,
    )
    .await?;
    signing::generate_test_vector(client, &mut ctx.wallet, &tx).await;

    if args.tx.dump_tx {
        tx::dump_tx(&args.tx, tx);
    } else {
        signing::sign_tx(&mut ctx.wallet, &args.tx, &mut tx, signing_data);

        tx::process_tx(client, &mut ctx.wallet, &args.tx, tx).await?;
    }

    Ok(())
}

pub async fn submit_unjail_validator<
    C: namada::ledger::queries::Client + Sync,
>(
    client: &C,
    mut ctx: Context,
    args: args::TxUnjailValidator,
) -> Result<(), tx::Error>
where
    C: namada::ledger::queries::Client + Sync,
    C::Error: std::fmt::Display,
{
    let default_signer = Some(args.validator.clone());
    let signing_data = signing::aux_signing_data(
        client,
        &mut ctx.wallet,
        &args.tx,
        &Some(args.validator.clone()),
        default_signer,
    )
    .await?;

    let mut tx = tx::build_unjail_validator(
        client,
        args.clone(),
        &signing_data.gas_payer,
    )
    .await?;
    signing::generate_test_vector(client, &mut ctx.wallet, &tx).await;

    if args.tx.dump_tx {
        tx::dump_tx(&args.tx, tx);
    } else {
        signing::sign_tx(&mut ctx.wallet, &args.tx, &mut tx, signing_data);

        tx::process_tx(client, &mut ctx.wallet, &args.tx, tx).await?;
    }

    Ok(())
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
pub async fn broadcast_tx<C>(
    rpc_cli: &C,
    to_broadcast: &TxBroadcastData,
) -> Result<Response, tx::Error>
where
    C: namada::ledger::queries::Client + Sync,
    C::Error: std::fmt::Display,
{
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
pub async fn submit_tx<C>(
    client: &C,
    to_broadcast: TxBroadcastData,
) -> Result<TxResponse, tx::Error>
where
    C: namada::ledger::queries::Client + Sync,
    C::Error: std::fmt::Display,
{
    tx::submit_tx(client, to_broadcast).await
}

#[cfg(test)]
mod test_tx {
    use masp_primitives::transaction::components::Amount;
    use namada::ledger::masp::{make_asset_type, MaspAmount};
    use namada::types::address::testing::gen_established_address;
    use namada::types::token::MaspDenom;

    use super::*;

    #[test]
    fn test_masp_add_amount() {
        let address_1 = gen_established_address();
        let denom_1 = MaspDenom::One;
        let denom_2 = MaspDenom::Three;
        let epoch = Epoch::default();
        let _masp_amount = MaspAmount::default();

        let asset_base = make_asset_type(Some(epoch), &address_1, denom_1);
        let _asset_denom = make_asset_type(Some(epoch), &address_1, denom_2);
        let _asset_prefix = make_asset_type(Some(epoch), &address_1, denom_1);

        let _amount_base =
            Amount::from_pair(asset_base, 16).expect("Test failed");
        let _amount_denom =
            Amount::from_pair(asset_base, 2).expect("Test failed");
        let _amount_prefix =
            Amount::from_pair(asset_base, 4).expect("Test failed");

        // masp_amount += amount_base;
        // assert_eq!(masp_amount.get((epoch,)), Uint::zero());
        // Amount::from_pair(atype, amount)
        // MaspDenom::One
        // assert_eq!(zero.abs(), Uint::zero());
    }
}
