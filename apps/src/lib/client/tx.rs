use std::env;
use std::fmt::Debug;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::PathBuf;

use async_trait::async_trait;
use borsh::{BorshDeserialize, BorshSerialize};
use masp_proofs::prover::LocalTxProver;
use namada::core::ledger::governance::cli::offline::{
    OfflineSignedProposal, OfflineVote,
};
use namada::core::ledger::governance::cli::onchain::{
    DefaultProposal, PgfFundingProposal, PgfStewardProposal,
};
use namada::ledger::queries::Client;
use namada::ledger::rpc::{TxBroadcastData, TxResponse};
use namada::ledger::wallet::{Wallet, WalletUtils};
use namada::ledger::{masp, pos, signing, tx};
use namada::proof_of_stake::parameters::PosParams;
use namada::proto::Tx;
use namada::types::address::{Address, ImplicitAddress};
use namada::types::dec::Dec;
use namada::types::key::{self, *};
use namada::types::transaction::pos::InitValidator;
use namada::types::tx::TxBuilder;

use super::rpc;
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
            let gas_payer = if let Some(gas_payer) =
                args.clone().gas_payer.or(args.signing_keys.get(0).cloned())
            {
                gas_payer
            } else {
                return Err(tx::Error::InvalidFeePayer);
            };

            let tx_builder = tx::build_reveal_pk::<C>(
                client,
                &args,
                address,
                &public_key,
                &gas_payer.ref_to(),
            )
            .await?;

            let tx_builder = tx_builder.add_gas_payer(gas_payer);

            tx::process_tx(client, &mut ctx.wallet, &args, tx_builder.build())
                .await?;
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
    let default_signer = signing::signer_from_address(Some(args.owner.clone()));
    let signing_data = signing::aux_signing_data(
        client,
        &mut ctx.wallet,
        &args.tx,
        &args.owner,
        default_signer,
    )
    .await?;

    submit_reveal_aux(client, ctx, args.tx.clone(), &args.owner).await?;

    let tx_builder =
        tx::build_custom(client, args.clone(), &signing_data.gas_payer).await?;

    if args.tx.dump_tx {
        tx::dump_tx(&args.tx, tx_builder);
    } else {
        let tx_builder = signing::sign_tx(
            &mut ctx.wallet,
            &args.tx,
            tx_builder,
            signing_data,
        )?;
        tx::process_tx(client, &mut ctx.wallet, &args.tx, tx_builder.build())
            .await?;
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
    let default_signer = signing::signer_from_address(Some(args.addr.clone()));
    let signing_data = signing::aux_signing_data(
        client,
        &mut ctx.wallet,
        &args.tx,
        &args.addr,
        default_signer,
    )
    .await?;

    let tx_builder =
        tx::build_update_account(client, args.clone(), &signing_data.gas_payer)
            .await?;

    if args.tx.dump_tx {
        tx::dump_tx(&args.tx, tx_builder);
    } else {
        let tx_builder = signing::sign_tx(
            &mut ctx.wallet,
            &args.tx,
            tx_builder,
            signing_data,
        )?;
        tx::process_tx(client, &mut ctx.wallet, &args.tx, tx_builder.build())
            .await?;
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
    let gas_payer = if let Some(gas_payer) = args.tx.gas_payer.clone().or(args
        .tx
        .signing_keys
        .get(0)
        .cloned())
    {
        gas_payer
    } else {
        return Err(tx::Error::InvalidFeePayer);
    };

    let tx_builder =
        tx::build_init_account(client, args.clone(), &gas_payer.ref_to())
            .await?;

    if args.tx.dump_tx {
        tx::dump_tx(&args.tx, tx_builder);
    } else {
        let tx_builder = tx_builder.add_gas_payer(gas_payer);
        tx::process_tx(client, &mut ctx.wallet, &args.tx, tx_builder.build())
            .await?;
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
    let tx_builder = TxBuilder::new(chain_id, tx_args.expiration);

    let (tx_builder, extra_section_hash) =
        tx_builder.add_extra_section_from_hash(validator_vp_code_hash);

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

    let tx_builder = tx_builder.add_code_from_hash(tx_code_hash).add_data(data);

    let gas_payer = if let Some(gas_payer) = tx_args
        .gas_payer
        .clone()
        .or(tx_args.signing_keys.get(0).cloned())
    {
        gas_payer
    } else {
        return Err(tx::Error::InvalidFeePayer);
    };

    let tx_builder = tx::prepare_tx(
        client,
        &tx_args,
        tx_builder,
        gas_payer.ref_to(),
        #[cfg(not(feature = "mainnet"))]
        false,
    )
    .await?;

    if tx_args.dump_tx {
        tx::dump_tx(&tx_args, tx_builder);
    } else {
        let tx_builder = tx_builder.add_gas_payer(gas_payer);

        let result = tx::process_tx(
            client,
            &mut ctx.wallet,
            &tx_args,
            tx_builder.build(),
        )
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
        let default_signer =
            signing::signer_from_address(Some(args.source.effective_address()));
        let signing_data = signing::aux_signing_data(
            client,
            &mut ctx.wallet,
            &args.tx,
            &args.source.effective_address(),
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
        let (tx_builder, tx_epoch) = tx::build_transfer(
            client,
            &mut ctx.shielded,
            arg,
            &signing_data.gas_payer,
        )
        .await?;

        if args.tx.dump_tx {
            tx::dump_tx(&args.tx, tx_builder);
        } else {
            let tx_builder = signing::sign_tx(
                &mut ctx.wallet,
                &args.tx,
                tx_builder,
                signing_data,
            )?;
            let result = tx::process_tx(
                client,
                &mut ctx.wallet,
                &args.tx,
                tx_builder.build(),
            )
            .await?;

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
    let default_signer =
        signing::signer_from_address(Some(args.source.clone()));
    let signing_data = signing::aux_signing_data(
        client,
        &mut ctx.wallet,
        &args.tx,
        &args.source,
        default_signer,
    )
    .await?;

    submit_reveal_aux(client, &mut ctx, args.tx.clone(), &args.source).await?;

    let tx_builder =
        tx::build_ibc_transfer(client, args.clone(), &signing_data.gas_payer)
            .await?;

    if args.tx.dump_tx {
        tx::dump_tx(&args.tx, tx_builder);
    } else {
        let tx_builder = signing::sign_tx(
            &mut ctx.wallet,
            &args.tx,
            tx_builder,
            signing_data,
        )?;
        tx::process_tx(client, &mut ctx.wallet, &args.tx, tx_builder.build())
            .await?;
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
    let current_epoch = rpc::query_and_print_epoch(client).await;
    let governance_parameters = rpc::query_governance_parameters(client).await;

    let (tx_builder, signing_data) = if args.is_offline {
        let proposal = namada::core::ledger::governance::cli::offline::OfflineProposal::try_from(args.proposal_data.as_ref()).map_err(|e| tx::Error::FailedGovernaneProposalDeserialize(e.to_string()))?.validate(current_epoch)
        .map_err(|e| tx::Error::InvalidProposal(e.to_string()))?;

        let default_signer =
            signing::signer_from_address(Some(proposal.author.clone()));
        let signing_data = signing::aux_signing_data(
            client,
            &mut ctx.wallet,
            &args.tx,
            &proposal.author,
            default_signer,
        )
        .await?;

        let signed_offline_proposal = proposal
            .sign(args.tx.signing_keys, &signing_data.account_public_keys_map);
        let output_file_path =
            signed_offline_proposal.serialize().map_err(|e| {
                tx::Error::FailedGovernaneProposalDeserialize(e.to_string())
            })?;

        println!("Proposal serialized to: {}", output_file_path);
        return Ok(());
    } else if args.is_pgf_funding {
        let proposal =
            PgfFundingProposal::try_from(args.proposal_data.as_ref())
                .map_err(|e| {
                    tx::Error::FailedGovernaneProposalDeserialize(e.to_string())
                })?
                .validate(&governance_parameters, current_epoch)
                .map_err(|e| tx::Error::InvalidProposal(e.to_string()))?;

        let default_signer = signing::signer_from_address(Some(
            proposal.proposal.author.clone(),
        ));
        let signing_data = signing::aux_signing_data(
            client,
            &mut ctx.wallet,
            &args.tx,
            &proposal.proposal.author,
            default_signer,
        )
        .await?;

        submit_reveal_aux(
            client,
            &mut ctx,
            args.tx.clone(),
            &proposal.proposal.author,
        )
        .await?;

        (
            tx::build_pgf_funding_proposal(
                client,
                args.clone(),
                proposal,
                &signing_data.gas_payer,
            )
            .await?,
            signing_data,
        )
    } else if args.is_pgf_stewards {
        let proposal = PgfStewardProposal::try_from(
            args.proposal_data.as_ref(),
        )
        .map_err(|e| {
            tx::Error::FailedGovernaneProposalDeserialize(e.to_string())
        })?;
        let author_balane = rpc::get_token_balance(
            client,
            &ctx.native_token,
            &proposal.proposal.author,
        )
        .await;
        let proposal = proposal
            .validate(&governance_parameters, current_epoch, author_balane)
            .map_err(|e| tx::Error::InvalidProposal(e.to_string()))?;

        let default_signer = signing::signer_from_address(Some(
            proposal.proposal.author.clone(),
        ));
        let signing_data = signing::aux_signing_data(
            client,
            &mut ctx.wallet,
            &args.tx,
            &proposal.proposal.author,
            default_signer,
        )
        .await?;

        submit_reveal_aux(
            client,
            &mut ctx,
            args.tx.clone(),
            &proposal.proposal.author,
        )
        .await?;

        (
            tx::build_pgf_stewards_proposal(
                client,
                args.clone(),
                proposal,
                &signing_data.gas_payer,
            )
            .await?,
            signing_data,
        )
    } else {
        let proposal = DefaultProposal::try_from(args.proposal_data.as_ref())
            .map_err(|e| {
            tx::Error::FailedGovernaneProposalDeserialize(e.to_string())
        })?;
        let author_balane = rpc::get_token_balance(
            client,
            &ctx.native_token,
            &proposal.proposal.author,
        )
        .await;
        let proposal = proposal
            .validate(&governance_parameters, current_epoch, author_balane)
            .map_err(|e| tx::Error::InvalidProposal(e.to_string()))?;

        let default_signer = signing::signer_from_address(Some(
            proposal.proposal.author.clone(),
        ));
        let signing_data = signing::aux_signing_data(
            client,
            &mut ctx.wallet,
            &args.tx,
            &proposal.proposal.author,
            default_signer,
        )
        .await?;

        submit_reveal_aux(
            client,
            &mut ctx,
            args.tx.clone(),
            &proposal.proposal.author,
        )
        .await?;

        (
            tx::build_default_proposal(
                client,
                args.clone(),
                proposal,
                &signing_data.gas_payer,
            )
            .await?,
            signing_data,
        )
    };

    if args.tx.dump_tx {
        tx::dump_tx(&args.tx, tx_builder);
    } else {
        let tx_builder = signing::sign_tx(
            &mut ctx.wallet,
            &args.tx,
            tx_builder,
            signing_data,
        )?;
        tx::process_tx(client, &mut ctx.wallet, &args.tx, tx_builder.build())
            .await?;
    }

    Ok(())
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
    let current_epoch = rpc::query_and_print_epoch(client).await;

    let default_signer = signing::signer_from_address(Some(args.voter.clone()));
    let signing_data = signing::aux_signing_data(
        client,
        &mut ctx.wallet,
        &args.tx,
        &args.voter,
        default_signer.clone(),
    )
    .await?;

    let tx_builder = if args.is_offline {
        let proposal_vote = namada::core::ledger::governance::cli::onchain::ProposalVote::try_from(args.vote)
            .map_err(|_| tx::Error::InvalidProposalVote)?;

        let proposal = OfflineSignedProposal::try_from(
            args.proposal_data.unwrap().as_ref(),
        )
        .map_err(|e| tx::Error::InvalidProposal(e.to_string()))?
        .validate(
            &signing_data.account_public_keys_map,
            signing_data.threshold,
        )
        .map_err(|e| tx::Error::InvalidProposal(e.to_string()))?;
        let delegations = rpc::get_delegators_delegation_at(
            client,
            &args.voter,
            proposal.proposal.tally_epoch,
        )
        .await
        .keys()
        .cloned()
        .collect::<Vec<Address>>();

        let offline_vote = OfflineVote::new(
            &proposal,
            proposal_vote,
            args.voter.clone(),
            delegations,
        );

        let offline_signed_vote = offline_vote
            .sign(args.tx.signing_keys, &signing_data.account_public_keys_map);
        let output_file_path = offline_signed_vote
            .serialize()
            .expect("Should be able to serialize the offline proposal");

        println!("Proposal vote serialized to: {}", output_file_path);
        return Ok(());
    } else {
        tx::build_vote_proposal(
            client,
            args.clone(),
            current_epoch,
            &signing_data.gas_payer,
        )
        .await?
    };

    if args.tx.dump_tx {
        tx::dump_tx(&args.tx, tx_builder);
    } else {
        let tx_builder = signing::sign_tx(
            &mut ctx.wallet,
            &args.tx,
            tx_builder,
            signing_data,
        )?;
        tx::process_tx(client, &mut ctx.wallet, &args.tx, tx_builder.build())
            .await?;
    }

    Ok(())
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

    let default_signer = signing::signer_from_address(Some(owner.clone()));
    let signing_data = signing::aux_signing_data(
        client,
        &mut ctx.wallet,
        &tx_args,
        &owner,
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

    let signatures = tx.compute_section_signature(
        secret_keys,
        &signing_data.account_public_keys_map,
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
            &signing_data
                .account_public_keys_map
                .get_public_key_from_index(signature.index)
                .unwrap(),
            output_path.display()
        );
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
    let default_signer =
        signing::signer_from_address(Some(default_address.clone()));
    let signing_data = signing::aux_signing_data(
        client,
        &mut ctx.wallet,
        &args.tx,
        &default_address,
        default_signer,
    )
    .await?;

    submit_reveal_aux(client, ctx, args.tx.clone(), &default_address).await?;

    let tx_builder =
        tx::build_bond::<C>(client, args.clone(), &signing_data.gas_payer)
            .await?;

    if args.tx.dump_tx {
        tx::dump_tx(&args.tx, tx_builder);
    } else {
        let tx_builder = signing::sign_tx(
            &mut ctx.wallet,
            &args.tx,
            tx_builder,
            signing_data,
        )?;

        tx::process_tx(client, &mut ctx.wallet, &args.tx, tx_builder.build())
            .await?;
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
    let default_signer =
        signing::signer_from_address(Some(default_address.clone()));
    let signing_data = signing::aux_signing_data(
        client,
        &mut ctx.wallet,
        &args.tx,
        &default_address,
        default_signer,
    )
    .await?;

    let (tx_builder, latest_withdrawal_pre) = tx::build_unbond(
        client,
        &mut ctx.wallet,
        args.clone(),
        &signing_data.gas_payer,
    )
    .await?;

    if args.tx.dump_tx {
        tx::dump_tx(&args.tx, tx_builder);
    } else {
        let tx_builder = signing::sign_tx(
            &mut ctx.wallet,
            &args.tx,
            tx_builder,
            signing_data,
        )?;

        tx::process_tx(client, &mut ctx.wallet, &args.tx, tx_builder.build())
            .await?;

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
    let default_signer =
        signing::signer_from_address(Some(default_address.clone()));
    let signing_data = signing::aux_signing_data(
        client,
        &mut ctx.wallet,
        &args.tx,
        &default_address,
        default_signer,
    )
    .await?;

    let tx_builder =
        tx::build_withdraw(client, args.clone(), &signing_data.gas_payer)
            .await?;

    if args.tx.dump_tx {
        tx::dump_tx(&args.tx, tx_builder);
    } else {
        let tx_builder = signing::sign_tx(
            &mut ctx.wallet,
            &args.tx,
            tx_builder,
            signing_data,
        )?;

        tx::process_tx(client, &mut ctx.wallet, &args.tx, tx_builder.build())
            .await?;
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
    let default_signer =
        signing::signer_from_address(Some(args.validator.clone()));
    let signing_data = signing::aux_signing_data(
        client,
        &mut ctx.wallet,
        &args.tx,
        &args.validator,
        default_signer,
    )
    .await?;

    let tx_builder = tx::build_validator_commission_change(
        client,
        args.clone(),
        &signing_data.gas_payer,
    )
    .await?;

    if args.tx.dump_tx {
        tx::dump_tx(&args.tx, tx_builder);
    } else {
        let tx_builder = signing::sign_tx(
            &mut ctx.wallet,
            &args.tx,
            tx_builder,
            signing_data,
        )?;

        tx::process_tx(client, &mut ctx.wallet, &args.tx, tx_builder.build())
            .await?;
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
    let default_signer =
        signing::signer_from_address(Some(args.validator.clone()));
    let signing_data = signing::aux_signing_data(
        client,
        &mut ctx.wallet,
        &args.tx,
        &args.validator,
        default_signer,
    )
    .await?;

    let tx_builder = tx::build_unjail_validator(
        client,
        args.clone(),
        &signing_data.gas_payer,
    )
    .await?;

    if args.tx.dump_tx {
        tx::dump_tx(&args.tx, tx_builder);
    } else {
        let tx_builder = signing::sign_tx(
            &mut ctx.wallet,
            &args.tx,
            tx_builder,
            signing_data,
        )?;

        tx::process_tx(client, &mut ctx.wallet, &args.tx, tx_builder.build())
            .await?;
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
    use namada::core::types::storage::Epoch;
    use namada::ledger::masp::{make_asset_type, MaspAmount};
    use namada::types::address::testing::gen_established_address;
    use namada::types::token::MaspDenom;

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
