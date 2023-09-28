use std::fs::File;

use namada::core::ledger::governance::cli::offline::{
    OfflineProposal, OfflineSignedProposal, OfflineVote,
};
use namada::core::ledger::governance::cli::onchain::{
    DefaultProposal, PgfFundingProposal, PgfStewardProposal, ProposalVote,
};
use namada::ledger::rpc::{TxBroadcastData, TxResponse};
use namada::ledger::wallet::{Wallet, WalletIo};
use namada::ledger::{pos, signing, tx, Namada, NamadaImpl};
use namada::proof_of_stake::parameters::PosParams;
use namada::proto::Tx;
use namada::tendermint_rpc::HttpClient;
use namada::types::address::{Address, ImplicitAddress};
use namada::types::dec::Dec;
use namada::types::error;
use namada::types::key::{self, *};
use namada::types::transaction::pos::InitValidator;

use super::rpc;
use crate::cli::{args, safe_exit, Context};
use crate::client::rpc::query_wasm_code_hash;
use crate::client::tx::tx::ProcessTxResponse;
use crate::config::TendermintMode;
use crate::facade::tendermint_rpc::endpoint::broadcast::tx_sync::Response;
use crate::node::ledger::tendermint_node;
use crate::wallet::{
    gen_validator_keys, read_and_confirm_encryption_password, CliWalletUtils,
};

/// Wrapper around `signing::aux_signing_data` that stores the optional
/// disposable address to the wallet
pub async fn aux_signing_data<'a>(
    context: &mut impl Namada<'a, WalletUtils = CliWalletUtils>,
    args: &args::Tx,
    owner: Option<Address>,
    default_signer: Option<Address>,
) -> Result<signing::SigningTxData, error::Error> {
    let signing_data =
        signing::aux_signing_data(context, args, owner, default_signer).await?;

    if args.disposable_signing_key {
        if !(args.dry_run || args.dry_run_wrapper) {
            // Store the generated signing key to wallet in case of need
            crate::wallet::save(context.wallet).map_err(|_| {
                error::Error::Other(
                    "Failed to save disposable address to wallet".to_string(),
                )
            })?;
        } else {
            println!(
                "Transaction dry run. The disposable address will not be \
                 saved to wallet."
            )
        }
    }

    Ok(signing_data)
}

// Build a transaction to reveal the signer of the given transaction.
pub async fn submit_reveal_aux<'a>(
    context: &mut impl Namada<'a>,
    args: args::Tx,
    address: &Address,
) -> Result<(), error::Error> {
    if args.dump_tx {
        return Ok(());
    }

    if let Address::Implicit(ImplicitAddress(pkh)) = address {
        let key = context
            .wallet
            .find_key_by_pkh(pkh, args.clone().password)
            .map_err(|e| error::Error::Other(e.to_string()))?;
        let public_key = key.ref_to();

        if tx::is_reveal_pk_needed(context.client, address, args.force).await? {
            println!(
                "Submitting a tx to reveal the public key for address \
                 {address}..."
            );
            let (mut tx, signing_data, _epoch) =
                tx::build_reveal_pk(context, &args, &public_key).await?;

            signing::generate_test_vector(context, &tx).await?;

            context.sign(&mut tx, &args, signing_data)?;

            context.submit(tx, &args).await?;
        }
    }

    Ok(())
}

pub async fn submit_custom<C: namada::ledger::queries::Client + Sync>(
    client: &C,
    ctx: &mut Context,
    args: args::TxCustom,
) -> Result<(), error::Error>
where
    C::Error: std::fmt::Display,
{
    let mut namada =
        NamadaImpl::new(client, &mut ctx.wallet, &mut ctx.shielded);
    submit_reveal_aux(&mut namada, args.tx.clone(), &args.owner).await?;

    let (mut tx, signing_data, _epoch) = args.build(&mut namada).await?;

    signing::generate_test_vector(&mut namada, &tx).await?;

    if args.tx.dump_tx {
        tx::dump_tx(&args.tx, tx);
    } else {
        namada.sign(&mut tx, &args.tx, signing_data)?;
        namada.submit(tx, &args.tx).await?;
    }

    Ok(())
}

pub async fn submit_update_account<C>(
    client: &C,
    ctx: &mut Context,
    args: args::TxUpdateAccount,
) -> Result<(), error::Error>
where
    C: namada::ledger::queries::Client + Sync,
    C::Error: std::fmt::Display,
{
    let mut namada =
        NamadaImpl::new(client, &mut ctx.wallet, &mut ctx.shielded);
    let (mut tx, signing_data, _epoch) = args.build(&mut namada).await?;

    signing::generate_test_vector(&mut namada, &tx).await?;

    if args.tx.dump_tx {
        tx::dump_tx(&args.tx, tx);
    } else {
        namada.sign(&mut tx, &args.tx, signing_data)?;
        namada.submit(tx, &args.tx).await?;
    }

    Ok(())
}

pub async fn submit_init_account<C: namada::ledger::queries::Client + Sync>(
    client: &C,
    ctx: &mut Context,
    args: args::TxInitAccount,
) -> Result<(), error::Error>
where
    C::Error: std::fmt::Display,
{
    let mut namada =
        NamadaImpl::new(client, &mut ctx.wallet, &mut ctx.shielded);
    let (mut tx, signing_data, _epoch) =
        tx::build_init_account(&mut namada, &args).await?;

    signing::generate_test_vector(&mut namada, &tx).await?;

    if args.tx.dump_tx {
        tx::dump_tx(&args.tx, tx);
    } else {
        namada.sign(&mut tx, &args.tx, signing_data)?;
        namada.submit(tx, &args.tx).await?;
    }

    Ok(())
}

pub async fn submit_init_validator<
    C: namada::ledger::queries::Client + Sync,
>(
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
) -> Result<(), error::Error> {
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
                    None,
                    password,
                    None,
                )
                .expect("Key generation should not fail.")
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
                    None,
                    password,
                    None,
                )
                .expect("Key generation should not fail.")
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
                    None,
                    password,
                    None,
                )
                .expect("Key generation should not fail.")
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

    let validator_vp_code_hash =
        query_wasm_code_hash(client, validator_vp_code_path.to_str().unwrap())
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

    let mut namada =
        NamadaImpl::new(client, &mut ctx.wallet, &mut ctx.shielded);
    let signing_data =
        aux_signing_data(&mut namada, &tx_args, None, None).await?;

    tx::prepare_tx(
        &mut namada,
        &tx_args,
        &mut tx,
        signing_data.fee_payer.clone(),
        None,
        #[cfg(not(feature = "mainnet"))]
        false,
    )
    .await?;

    signing::generate_test_vector(&mut namada, &tx).await?;

    if tx_args.dump_tx {
        tx::dump_tx(&tx_args, tx);
    } else {
        namada.sign(&mut tx, &tx_args, signing_data)?;

        let result = namada.submit(tx, &tx_args).await?.initialized_accounts();

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

pub async fn submit_transfer<C: namada::ledger::queries::Client + Sync>(
    client: &C,
    mut ctx: Context,
    args: args::TxTransfer,
) -> Result<(), error::Error> {
    for _ in 0..2 {
        let mut namada =
            NamadaImpl::new(client, &mut ctx.wallet, &mut ctx.shielded);

        submit_reveal_aux(
            &mut namada,
            args.tx.clone(),
            &args.source.effective_address(),
        )
        .await?;

        let (mut tx, signing_data, tx_epoch) =
            args.clone().build(&mut namada).await?;
        signing::generate_test_vector(&mut namada, &tx).await?;

        if args.tx.dump_tx {
            tx::dump_tx(&args.tx, tx);
            break;
        } else {
            namada.sign(&mut tx, &args.tx, signing_data)?;
            let result = namada.submit(tx, &args.tx).await?;

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

pub async fn submit_ibc_transfer<C: namada::ledger::queries::Client + Sync>(
    client: &C,
    mut ctx: Context,
    args: args::TxIbcTransfer,
) -> Result<(), error::Error>
where
    C::Error: std::fmt::Display,
{
    let mut namada =
        NamadaImpl::new(client, &mut ctx.wallet, &mut ctx.shielded);
    submit_reveal_aux(&mut namada, args.tx.clone(), &args.source).await?;
    let (mut tx, signing_data, _epoch) = args.build(&mut namada).await?;
    signing::generate_test_vector(&mut namada, &tx).await?;

    if args.tx.dump_tx {
        tx::dump_tx(&args.tx, tx);
    } else {
        namada.sign(&mut tx, &args.tx, signing_data)?;
        namada.submit(tx, &args.tx).await?;
    }

    Ok(())
}

pub async fn submit_init_proposal<C: namada::ledger::queries::Client + Sync>(
    client: &C,
    mut ctx: Context,
    args: args::InitProposal,
) -> Result<(), error::Error>
where
    C::Error: std::fmt::Display,
{
    let current_epoch = rpc::query_and_print_epoch(client).await;
    let governance_parameters = rpc::query_governance_parameters(client).await;
    let mut namada =
        NamadaImpl::new(client, &mut ctx.wallet, &mut ctx.shielded);
    let (mut tx_builder, signing_data, _fee_unshield_epoch) = if args.is_offline
    {
        let proposal = OfflineProposal::try_from(args.proposal_data.as_ref())
            .map_err(|e| {
                error::TxError::FailedGovernaneProposalDeserialize(
                    e.to_string(),
                )
            })?
            .validate(current_epoch, args.tx.force)
            .map_err(|e| error::TxError::InvalidProposal(e.to_string()))?;

        let default_signer = Some(proposal.author.clone());
        let signing_data = aux_signing_data(
            &mut namada,
            &args.tx,
            Some(proposal.author.clone()),
            default_signer,
        )
        .await?;

        let signed_offline_proposal = proposal.sign(
            args.tx.signing_keys,
            &signing_data.account_public_keys_map.unwrap(),
        );
        let output_file_path = signed_offline_proposal
            .serialize(args.tx.output_folder)
            .map_err(|e| {
                error::TxError::FailedGovernaneProposalDeserialize(
                    e.to_string(),
                )
            })?;

        println!("Proposal serialized to: {}", output_file_path);
        return Ok(());
    } else if args.is_pgf_funding {
        let proposal =
            PgfFundingProposal::try_from(args.proposal_data.as_ref())
                .map_err(|e| {
                    error::TxError::FailedGovernaneProposalDeserialize(
                        e.to_string(),
                    )
                })?
                .validate(&governance_parameters, current_epoch, args.tx.force)
                .map_err(|e| error::TxError::InvalidProposal(e.to_string()))?;

        submit_reveal_aux(
            &mut namada,
            args.tx.clone(),
            &proposal.proposal.author,
        )
        .await?;

        tx::build_pgf_funding_proposal(&mut namada, &args, proposal).await?
    } else if args.is_pgf_stewards {
        let proposal = PgfStewardProposal::try_from(
            args.proposal_data.as_ref(),
        )
        .map_err(|e| {
            error::TxError::FailedGovernaneProposalDeserialize(e.to_string())
        })?;
        let author_balance = rpc::get_token_balance(
            client,
            &ctx.native_token,
            &proposal.proposal.author,
        )
        .await;
        let proposal = proposal
            .validate(
                &governance_parameters,
                current_epoch,
                author_balance,
                args.tx.force,
            )
            .map_err(|e| error::TxError::InvalidProposal(e.to_string()))?;

        submit_reveal_aux(
            &mut namada,
            args.tx.clone(),
            &proposal.proposal.author,
        )
        .await?;

        tx::build_pgf_stewards_proposal(&mut namada, &args, proposal).await?
    } else {
        let proposal = DefaultProposal::try_from(args.proposal_data.as_ref())
            .map_err(|e| {
            error::TxError::FailedGovernaneProposalDeserialize(e.to_string())
        })?;
        let author_balane = rpc::get_token_balance(
            client,
            &ctx.native_token,
            &proposal.proposal.author,
        )
        .await;
        let proposal = proposal
            .validate(
                &governance_parameters,
                current_epoch,
                author_balane,
                args.tx.force,
            )
            .map_err(|e| error::TxError::InvalidProposal(e.to_string()))?;

        submit_reveal_aux(
            &mut namada,
            args.tx.clone(),
            &proposal.proposal.author,
        )
        .await?;

        tx::build_default_proposal(&mut namada, &args, proposal).await?
    };
    signing::generate_test_vector(&mut namada, &tx_builder).await?;

    if args.tx.dump_tx {
        tx::dump_tx(&args.tx, tx_builder);
    } else {
        namada.sign(&mut tx_builder, &args.tx, signing_data)?;
        namada.submit(tx_builder, &args.tx).await?;
    }

    Ok(())
}

pub async fn submit_vote_proposal<C: namada::ledger::queries::Client + Sync>(
    client: &C,
    mut ctx: Context,
    args: args::VoteProposal,
) -> Result<(), error::Error>
where
    C: namada::ledger::queries::Client + Sync,
    C::Error: std::fmt::Display,
{
    let mut namada =
        NamadaImpl::new(client, &mut ctx.wallet, &mut ctx.shielded);
    let (mut tx_builder, signing_data, _fee_unshield_epoch) = if args.is_offline
    {
        let default_signer = Some(args.voter.clone());
        let signing_data = aux_signing_data(
            &mut namada,
            &args.tx,
            Some(args.voter.clone()),
            default_signer.clone(),
        )
        .await?;

        let proposal_vote = ProposalVote::try_from(args.vote)
            .map_err(|_| error::TxError::InvalidProposalVote)?;

        let proposal = OfflineSignedProposal::try_from(
            args.proposal_data.clone().unwrap().as_ref(),
        )
        .map_err(|e| error::TxError::InvalidProposal(e.to_string()))?
        .validate(
            &signing_data.account_public_keys_map.clone().unwrap(),
            signing_data.threshold,
            args.tx.force,
        )
        .map_err(|e| error::TxError::InvalidProposal(e.to_string()))?;
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

        let offline_signed_vote = offline_vote.sign(
            args.tx.signing_keys,
            &signing_data.account_public_keys_map.unwrap(),
        );
        let output_file_path = offline_signed_vote
            .serialize(args.tx.output_folder)
            .expect("Should be able to serialize the offline proposal");

        println!("Proposal vote serialized to: {}", output_file_path);
        return Ok(());
    } else {
        args.build(&mut namada).await?
    };
    signing::generate_test_vector(&mut namada, &tx_builder).await?;

    if args.tx.dump_tx {
        tx::dump_tx(&args.tx, tx_builder);
    } else {
        namada.sign(&mut tx_builder, &args.tx, signing_data)?;
        namada.submit(tx_builder, &args.tx).await?;
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
) -> Result<(), error::Error>
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
    let mut namada =
        NamadaImpl::new(client, &mut ctx.wallet, &mut ctx.shielded);
    let default_signer = Some(owner.clone());
    let signing_data = aux_signing_data(
        &mut namada,
        &tx_args,
        Some(owner.clone()),
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

    if let Some(account_public_keys_map) = signing_data.account_public_keys_map
    {
        let signatures = tx.compute_section_signature(
            secret_keys,
            &account_public_keys_map,
            Some(owner),
        );

        for signature in &signatures {
            let filename = format!(
                "offline_signature_{}_{}.tx",
                tx.header_hash(),
                signature.pubkey,
            );
            let output_path = match &tx_args.output_folder {
                Some(path) => path.join(filename),
                None => filename.into(),
            };

            let signature_path = File::create(&output_path)
                .expect("Should be able to create signature file.");

            serde_json::to_writer_pretty(
                signature_path,
                &signature.serialize(),
            )
            .expect("Signature should be deserializable.");
            println!(
                "Signature for {} serialized at {}",
                signature.pubkey,
                output_path.display()
            );
        }
    }
    Ok(())
}

pub async fn submit_reveal_pk<C: namada::ledger::queries::Client + Sync>(
    client: &C,
    ctx: &mut Context,
    args: args::RevealPk,
) -> Result<(), error::Error>
where
    C::Error: std::fmt::Display,
{
    let mut namada =
        NamadaImpl::new(client, &mut ctx.wallet, &mut ctx.shielded);
    submit_reveal_aux(&mut namada, args.tx, &(&args.public_key).into()).await?;

    Ok(())
}

pub async fn submit_bond<C>(
    client: &C,
    ctx: &mut Context,
    args: args::Bond,
) -> Result<(), error::Error>
where
    C: namada::ledger::queries::Client + Sync,
    C::Error: std::fmt::Display,
{
    let mut namada =
        NamadaImpl::new(client, &mut ctx.wallet, &mut ctx.shielded);
    let default_address = args.source.clone().unwrap_or(args.validator.clone());
    submit_reveal_aux(&mut namada, args.tx.clone(), &default_address).await?;

    let (mut tx, signing_data, _fee_unshield_epoch) =
        args.build(&mut namada).await?;
    signing::generate_test_vector(&mut namada, &tx).await?;

    if args.tx.dump_tx {
        tx::dump_tx(&args.tx, tx);
    } else {
        namada.sign(&mut tx, &args.tx, signing_data)?;

        namada.submit(tx, &args.tx).await?;
    }

    Ok(())
}

pub async fn submit_unbond<C: namada::ledger::queries::Client + Sync>(
    client: &C,
    ctx: &mut Context,
    args: args::Unbond,
) -> Result<(), error::Error>
where
    C::Error: std::fmt::Display,
{
    let mut namada =
        NamadaImpl::new(client, &mut ctx.wallet, &mut ctx.shielded);
    let (mut tx, signing_data, _fee_unshield_epoch, latest_withdrawal_pre) =
        args.build(&mut namada).await?;
    signing::generate_test_vector(&mut namada, &tx).await?;

    if args.tx.dump_tx {
        tx::dump_tx(&args.tx, tx);
    } else {
        namada.sign(&mut tx, &args.tx, signing_data)?;

        namada.submit(tx, &args.tx).await?;

        tx::query_unbonds(client, args.clone(), latest_withdrawal_pre).await?;
    }

    Ok(())
}

pub async fn submit_withdraw<C: namada::ledger::queries::Client + Sync>(
    client: &C,
    mut ctx: Context,
    args: args::Withdraw,
) -> Result<(), error::Error>
where
    C::Error: std::fmt::Display,
{
    let mut namada =
        NamadaImpl::new(client, &mut ctx.wallet, &mut ctx.shielded);
    let (mut tx, signing_data, _fee_unshield_epoch) =
        args.build(&mut namada).await?;
    signing::generate_test_vector(&mut namada, &tx).await?;

    if args.tx.dump_tx {
        tx::dump_tx(&args.tx, tx);
    } else {
        namada.sign(&mut tx, &args.tx, signing_data)?;

        namada.submit(tx, &args.tx).await?;
    }

    Ok(())
}

pub async fn submit_validator_commission_change<
    C: namada::ledger::queries::Client + Sync,
>(
    client: &C,
    mut ctx: Context,
    args: args::CommissionRateChange,
) -> Result<(), error::Error>
where
    C::Error: std::fmt::Display,
{
    let mut namada =
        NamadaImpl::new(client, &mut ctx.wallet, &mut ctx.shielded);
    let (mut tx, signing_data, _fee_unshield_epoch) =
        args.build(&mut namada).await?;
    signing::generate_test_vector(&mut namada, &tx).await?;

    if args.tx.dump_tx {
        tx::dump_tx(&args.tx, tx);
    } else {
        namada.sign(&mut tx, &args.tx, signing_data)?;

        namada.submit(tx, &args.tx).await?;
    }

    Ok(())
}

pub async fn submit_unjail_validator<
    C: namada::ledger::queries::Client + Sync,
>(
    client: &C,
    mut ctx: Context,
    args: args::TxUnjailValidator,
) -> Result<(), error::Error>
where
    C::Error: std::fmt::Display,
{
    let mut namada =
        NamadaImpl::new(client, &mut ctx.wallet, &mut ctx.shielded);
    let (mut tx, signing_data, _fee_unshield_epoch) =
        args.build(&mut namada).await?;
    signing::generate_test_vector(&mut namada, &tx).await?;

    if args.tx.dump_tx {
        tx::dump_tx(&args.tx, tx);
    } else {
        namada.sign(&mut tx, &args.tx, signing_data)?;

        namada.submit(tx, &args.tx).await?;
    }

    Ok(())
}

pub async fn submit_update_steward_commission<
    C: namada::ledger::queries::Client + Sync,
>(
    client: &C,
    mut ctx: Context,
    args: args::UpdateStewardCommission,
) -> Result<(), error::Error>
where
    C: namada::ledger::queries::Client + Sync,
    C::Error: std::fmt::Display,
{
    let mut namada =
        NamadaImpl::new(client, &mut ctx.wallet, &mut ctx.shielded);
    let (mut tx, signing_data, _fee_unshield_epoch) =
        args.build(&mut namada).await?;

    signing::generate_test_vector(&mut namada, &tx).await?;

    if args.tx.dump_tx {
        tx::dump_tx(&args.tx, tx);
    } else {
        namada.sign(&mut tx, &args.tx, signing_data)?;
        namada.submit(tx, &args.tx).await?;
    }

    Ok(())
}

pub async fn submit_resign_steward<C: namada::ledger::queries::Client + Sync>(
    client: &C,
    mut ctx: Context,
    args: args::ResignSteward,
) -> Result<(), error::Error>
where
    C: namada::ledger::queries::Client + Sync,
    C::Error: std::fmt::Display,
{
    let mut namada =
        NamadaImpl::new(client, &mut ctx.wallet, &mut ctx.shielded);
    let (mut tx, signing_data, _epoch) = args.build(&mut namada).await?;

    signing::generate_test_vector(&mut namada, &tx).await?;

    if args.tx.dump_tx {
        tx::dump_tx(&args.tx, tx);
    } else {
        namada.sign(&mut tx, &args.tx, signing_data)?;
        namada.submit(tx, &args.tx).await?;
    }

    Ok(())
}

/// Save accounts initialized from a tx into the wallet, if any.
pub async fn save_initialized_accounts<U: WalletIo>(
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
pub async fn broadcast_tx(
    rpc_cli: &HttpClient,
    to_broadcast: &TxBroadcastData,
) -> Result<Response, error::Error> {
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
pub async fn submit_tx(
    client: &HttpClient,
    to_broadcast: TxBroadcastData,
) -> Result<TxResponse, error::Error> {
    tx::submit_tx(client, to_broadcast).await
}
