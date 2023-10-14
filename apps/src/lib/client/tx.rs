use std::fs::File;

use namada::core::ledger::governance::cli::offline::{
    OfflineProposal, OfflineSignedProposal, OfflineVote,
};
use namada::core::ledger::governance::cli::onchain::{
    DefaultProposal, PgfFundingProposal, PgfStewardProposal, ProposalVote,
};
use namada::ledger::pos;
use namada::proof_of_stake::parameters::PosParams;
use namada::proto::Tx;
use namada::types::address::{Address, ImplicitAddress};
use namada::types::dec::Dec;
use namada::types::io::Io;
use namada::types::key::{self, *};
use namada::types::transaction::pos::InitValidator;
use namada_sdk::rpc::{TxBroadcastData, TxResponse};
use namada_sdk::{display_line, edisplay_line, error, signing, tx, Namada};

use super::rpc;
use crate::cli::{args, safe_exit};
use crate::client::rpc::query_wasm_code_hash;
use crate::client::tx::tx::ProcessTxResponse;
use crate::config::TendermintMode;
use crate::facade::tendermint_rpc::endpoint::broadcast::tx_sync::Response;
use crate::node::ledger::tendermint_node;
use crate::wallet::{gen_validator_keys, read_and_confirm_encryption_password};

/// Wrapper around `signing::aux_signing_data` that stores the optional
/// disposable address to the wallet
pub async fn aux_signing_data<'a>(
    context: &impl Namada<'a>,
    args: &args::Tx,
    owner: Option<Address>,
    default_signer: Option<Address>,
) -> Result<signing::SigningTxData, error::Error> {
    let signing_data =
        signing::aux_signing_data(context, args, owner, default_signer).await?;

    if args.disposable_signing_key {
        if !(args.dry_run || args.dry_run_wrapper) {
            // Store the generated signing key to wallet in case of need
            context.wallet().await.save().map_err(|_| {
                error::Error::Other(
                    "Failed to save disposable address to wallet".to_string(),
                )
            })?;
        } else {
            display_line!(
                context.io(),
                "Transaction dry run. The disposable address will not be \
                 saved to wallet."
            )
        }
    }

    Ok(signing_data)
}

// Build a transaction to reveal the signer of the given transaction.
pub async fn submit_reveal_aux<'a>(
    context: &impl Namada<'a>,
    args: args::Tx,
    address: &Address,
) -> Result<(), error::Error> {
    if args.dump_tx {
        return Ok(());
    }

    if let Address::Implicit(ImplicitAddress(pkh)) = address {
        let key = context
            .wallet_mut()
            .await
            .find_key_by_pkh(pkh, args.clone().password)
            .map_err(|e| error::Error::Other(e.to_string()))?;
        let public_key = key.ref_to();

        if tx::is_reveal_pk_needed(context.client(), address, args.force)
            .await?
        {
            println!(
                "Submitting a tx to reveal the public key for address \
                 {address}..."
            );
            let (mut tx, signing_data, _epoch) =
                tx::build_reveal_pk(context, &args, &public_key).await?;

            signing::generate_test_vector(context, &tx).await?;

            context.sign(&mut tx, &args, signing_data).await?;

            context.submit(tx, &args).await?;
        }
    }

    Ok(())
}

pub async fn submit_bridge_pool_tx<'a, N: Namada<'a>>(
    namada: &N,
    args: args::EthereumBridgePool,
) -> Result<(), error::Error> {
    let tx_args = args.tx.clone();
    let (mut tx, signing_data, _epoch) = args.clone().build(namada).await?;

    signing::generate_test_vector(namada, &tx).await?;

    if args.tx.dump_tx {
        tx::dump_tx(namada.io(), &args.tx, tx);
    } else {
        submit_reveal_aux(namada, tx_args.clone(), &args.sender).await?;
        namada.sign(&mut tx, &tx_args, signing_data).await?;
        namada.submit(tx, &tx_args).await?;
    }

    Ok(())
}

pub async fn submit_custom<'a, N: Namada<'a>>(
    namada: &N,
    args: args::TxCustom,
) -> Result<(), error::Error>
where
    <N::Client as namada::ledger::queries::Client>::Error: std::fmt::Display,
{
    submit_reveal_aux(namada, args.tx.clone(), &args.owner).await?;

    let (mut tx, signing_data, _epoch) = args.build(namada).await?;

    signing::generate_test_vector(namada, &tx).await?;

    if args.tx.dump_tx {
        tx::dump_tx(namada.io(), &args.tx, tx);
    } else {
        namada.sign(&mut tx, &args.tx, signing_data).await?;
        namada.submit(tx, &args.tx).await?;
    }

    Ok(())
}

pub async fn submit_update_account<'a, N: Namada<'a>>(
    namada: &N,
    args: args::TxUpdateAccount,
) -> Result<(), error::Error>
where
    <N::Client as namada::ledger::queries::Client>::Error: std::fmt::Display,
{
    let (mut tx, signing_data, _epoch) = args.build(namada).await?;

    signing::generate_test_vector(namada, &tx).await?;

    if args.tx.dump_tx {
        tx::dump_tx(namada.io(), &args.tx, tx);
    } else {
        namada.sign(&mut tx, &args.tx, signing_data).await?;
        namada.submit(tx, &args.tx).await?;
    }

    Ok(())
}

pub async fn submit_init_account<'a, N: Namada<'a>>(
    namada: &N,
    args: args::TxInitAccount,
) -> Result<(), error::Error>
where
    <N::Client as namada::ledger::queries::Client>::Error: std::fmt::Display,
{
    let (mut tx, signing_data, _epoch) =
        tx::build_init_account(namada, &args).await?;

    signing::generate_test_vector(namada, &tx).await?;

    if args.tx.dump_tx {
        tx::dump_tx(namada.io(), &args.tx, tx);
    } else {
        namada.sign(&mut tx, &args.tx, signing_data).await?;
        namada.submit(tx, &args.tx).await?;
    }

    Ok(())
}

pub async fn submit_init_validator<'a>(
    namada: &impl Namada<'a>,
    config: &mut crate::config::Config,
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
            .or_else(|| Some(config.ledger.chain_id.clone())),
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

    let mut wallet = namada.wallet_mut().await;
    let consensus_key = consensus_key
        .map(|key| match key {
            common::SecretKey::Ed25519(_) => key,
            common::SecretKey::Secp256k1(_) => {
                edisplay_line!(
                    namada.io(),
                    "Consensus key can only be ed25519"
                );
                safe_exit(1)
            }
        })
        .unwrap_or_else(|| {
            display_line!(namada.io(), "Generating consensus key...");
            let password =
                read_and_confirm_encryption_password(unsafe_dont_encrypt);
            wallet
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
                edisplay_line!(
                    namada.io(),
                    "Eth cold key can only be secp256k1"
                );
                safe_exit(1)
            }
        })
        .unwrap_or_else(|| {
            display_line!(namada.io(), "Generating Eth cold key...");
            let password =
                read_and_confirm_encryption_password(unsafe_dont_encrypt);
            wallet
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
                edisplay_line!(
                    namada.io(),
                    "Eth hot key can only be secp256k1"
                );
                safe_exit(1)
            }
        })
        .unwrap_or_else(|| {
            display_line!(namada.io(), "Generating Eth hot key...");
            let password =
                read_and_confirm_encryption_password(unsafe_dont_encrypt);
            wallet
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
    // To avoid wallet deadlocks in following operations
    drop(wallet);

    if protocol_key.is_none() {
        display_line!(namada.io(), "Generating protocol signing key...");
    }
    // Generate the validator keys
    let validator_keys = gen_validator_keys(
        *namada.wallet_mut().await,
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
        query_wasm_code_hash(namada, validator_vp_code_path.to_str().unwrap())
            .await
            .unwrap();

    // Validate the commission rate data
    if commission_rate > Dec::one() || commission_rate < Dec::zero() {
        edisplay_line!(
            namada.io(),
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
        edisplay_line!(
            namada.io(),
            "The validator maximum change in commission rate per epoch must \
             not exceed 1.0 or 100%"
        );
        if !tx_args.force {
            safe_exit(1)
        }
    }
    let tx_code_hash =
        query_wasm_code_hash(namada, args::TX_INIT_VALIDATOR_WASM)
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

    let signing_data = aux_signing_data(namada, &tx_args, None, None).await?;

    tx::prepare_tx(
        namada,
        &tx_args,
        &mut tx,
        signing_data.fee_payer.clone(),
        None,
    )
    .await?;

    signing::generate_test_vector(namada, &tx).await?;

    if tx_args.dump_tx {
        tx::dump_tx(namada.io(), &tx_args, tx);
    } else {
        namada.sign(&mut tx, &tx_args, signing_data).await?;

        let result = namada.submit(tx, &tx_args).await?.initialized_accounts();

        if !tx_args.dry_run {
            let (validator_address_alias, validator_address) = match &result[..]
            {
                // There should be 1 account for the validator itself
                [validator_address] => {
                    if let Some(alias) =
                        namada.wallet().await.find_alias(validator_address)
                    {
                        (alias.clone(), validator_address.clone())
                    } else {
                        edisplay_line!(
                            namada.io(),
                            "Expected one account to be created"
                        );
                        safe_exit(1)
                    }
                }
                _ => {
                    edisplay_line!(
                        namada.io(),
                        "Expected one account to be created"
                    );
                    safe_exit(1)
                }
            };
            // add validator address and keys to the wallet
            namada
                .wallet_mut()
                .await
                .add_validator_data(validator_address, validator_keys);
            namada
                .wallet_mut()
                .await
                .save()
                .unwrap_or_else(|err| edisplay_line!(namada.io(), "{}", err));

            let tendermint_home = config.ledger.cometbft_dir();
            tendermint_node::write_validator_key(
                &tendermint_home,
                &consensus_key,
            );
            tendermint_node::write_validator_state(tendermint_home);

            // Write Namada config stuff or figure out how to do the above
            // tendermint_node things two epochs in the future!!!
            config.ledger.shell.tendermint_mode = TendermintMode::Validator;
            config
                .write(
                    &config.ledger.shell.base_dir,
                    &config.ledger.chain_id,
                    true,
                )
                .unwrap();

            let key = pos::params_key();
            let pos_params: PosParams =
                rpc::query_storage_value(namada.client(), &key)
                    .await
                    .expect("Pos parameter should be defined.");

            display_line!(namada.io(), "");
            display_line!(
                namada.io(),
                "The validator's addresses and keys were stored in the wallet:"
            );
            display_line!(
                namada.io(),
                "  Validator address \"{}\"",
                validator_address_alias
            );
            display_line!(
                namada.io(),
                "  Validator account key \"{}\"",
                validator_key_alias
            );
            display_line!(
                namada.io(),
                "  Consensus key \"{}\"",
                consensus_key_alias
            );
            display_line!(
                namada.io(),
                "The ledger node has been setup to use this validator's \
                 address and consensus key."
            );
            display_line!(
                namada.io(),
                "Your validator will be active in {} epochs. Be sure to \
                 restart your node for the changes to take effect!",
                pos_params.pipeline_len
            );
        } else {
            display_line!(
                namada.io(),
                "Transaction dry run. No addresses have been saved."
            );
        }
    }
    Ok(())
}

pub async fn submit_transfer<'a>(
    namada: &impl Namada<'a>,
    args: args::TxTransfer,
) -> Result<(), error::Error> {
    for _ in 0..2 {
        submit_reveal_aux(
            namada,
            args.tx.clone(),
            &args.source.effective_address(),
        )
        .await?;

        let (mut tx, signing_data, tx_epoch) =
            args.clone().build(namada).await?;
        signing::generate_test_vector(namada, &tx).await?;

        if args.tx.dump_tx {
            tx::dump_tx(namada.io(), &args.tx, tx);
            break;
        } else {
            namada.sign(&mut tx, &args.tx, signing_data).await?;
            let result = namada.submit(tx, &args.tx).await?;

            let submission_epoch = rpc::query_and_print_epoch(namada).await;

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
                    edisplay_line!(namada.io(),
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

pub async fn submit_ibc_transfer<'a, N: Namada<'a>>(
    namada: &N,
    args: args::TxIbcTransfer,
) -> Result<(), error::Error>
where
    <N::Client as namada::ledger::queries::Client>::Error: std::fmt::Display,
{
    submit_reveal_aux(namada, args.tx.clone(), &args.source).await?;
    let (mut tx, signing_data, _epoch) = args.build(namada).await?;
    signing::generate_test_vector(namada, &tx).await?;

    if args.tx.dump_tx {
        tx::dump_tx(namada.io(), &args.tx, tx);
    } else {
        namada.sign(&mut tx, &args.tx, signing_data).await?;
        namada.submit(tx, &args.tx).await?;
    }

    Ok(())
}

pub async fn submit_init_proposal<'a, N: Namada<'a>>(
    namada: &N,
    args: args::InitProposal,
) -> Result<(), error::Error>
where
    <N::Client as namada::ledger::queries::Client>::Error: std::fmt::Display,
{
    let current_epoch = rpc::query_and_print_epoch(namada).await;
    let governance_parameters =
        rpc::query_governance_parameters(namada.client()).await;
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
            namada,
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

        display_line!(
            namada.io(),
            "Proposal serialized to: {}",
            output_file_path
        );
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

        submit_reveal_aux(namada, args.tx.clone(), &proposal.proposal.author)
            .await?;

        tx::build_pgf_funding_proposal(namada, &args, proposal).await?
    } else if args.is_pgf_stewards {
        let proposal = PgfStewardProposal::try_from(
            args.proposal_data.as_ref(),
        )
        .map_err(|e| {
            error::TxError::FailedGovernaneProposalDeserialize(e.to_string())
        })?;
        let author_balance = rpc::get_token_balance(
            namada.client(),
            &namada.native_token(),
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

        submit_reveal_aux(namada, args.tx.clone(), &proposal.proposal.author)
            .await?;

        tx::build_pgf_stewards_proposal(namada, &args, proposal).await?
    } else {
        let proposal = DefaultProposal::try_from(args.proposal_data.as_ref())
            .map_err(|e| {
            error::TxError::FailedGovernaneProposalDeserialize(e.to_string())
        })?;
        let author_balane = rpc::get_token_balance(
            namada.client(),
            &namada.native_token(),
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

        submit_reveal_aux(namada, args.tx.clone(), &proposal.proposal.author)
            .await?;

        tx::build_default_proposal(namada, &args, proposal).await?
    };
    signing::generate_test_vector(namada, &tx_builder).await?;

    if args.tx.dump_tx {
        tx::dump_tx(namada.io(), &args.tx, tx_builder);
    } else {
        namada.sign(&mut tx_builder, &args.tx, signing_data).await?;
        namada.submit(tx_builder, &args.tx).await?;
    }

    Ok(())
}

pub async fn submit_vote_proposal<'a, N: Namada<'a>>(
    namada: &N,
    args: args::VoteProposal,
) -> Result<(), error::Error>
where
    <N::Client as namada::ledger::queries::Client>::Error: std::fmt::Display,
{
    let (mut tx_builder, signing_data, _fee_unshield_epoch) = if args.is_offline
    {
        let default_signer = Some(args.voter.clone());
        let signing_data = aux_signing_data(
            namada,
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
            namada.client(),
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

        display_line!(
            namada.io(),
            "Proposal vote serialized to: {}",
            output_file_path
        );
        return Ok(());
    } else {
        args.build(namada).await?
    };
    signing::generate_test_vector(namada, &tx_builder).await?;

    if args.tx.dump_tx {
        tx::dump_tx(namada.io(), &args.tx, tx_builder);
    } else {
        namada.sign(&mut tx_builder, &args.tx, signing_data).await?;
        namada.submit(tx_builder, &args.tx).await?;
    }

    Ok(())
}

pub async fn sign_tx<'a, N: Namada<'a>>(
    namada: &N,
    args::SignTx {
        tx: tx_args,
        tx_data,
        owner,
    }: args::SignTx,
) -> Result<(), error::Error>
where
    <N::Client as namada::ledger::queries::Client>::Error: std::fmt::Display,
{
    let tx = if let Ok(transaction) = Tx::deserialize(tx_data.as_ref()) {
        transaction
    } else {
        edisplay_line!(namada.io(), "Couldn't decode the transaction.");
        safe_exit(1)
    };
    let default_signer = Some(owner.clone());
    let signing_data =
        aux_signing_data(namada, &tx_args, Some(owner.clone()), default_signer)
            .await?;

    let mut wallet = namada.wallet_mut().await;
    let secret_keys = &signing_data
        .public_keys
        .iter()
        .filter_map(|public_key| {
            if let Ok(secret_key) =
                signing::find_key_by_pk(&mut wallet, &tx_args, public_key)
            {
                Some(secret_key)
            } else {
                edisplay_line!(
                    namada.io(),
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
            display_line!(
                namada.io(),
                "Signature for {} serialized at {}",
                signature.pubkey,
                output_path.display()
            );
        }
    }
    Ok(())
}

pub async fn submit_reveal_pk<'a, N: Namada<'a>>(
    namada: &N,
    args: args::RevealPk,
) -> Result<(), error::Error>
where
    <N::Client as namada::ledger::queries::Client>::Error: std::fmt::Display,
{
    submit_reveal_aux(namada, args.tx, &(&args.public_key).into()).await?;

    Ok(())
}

pub async fn submit_bond<'a, N: Namada<'a>>(
    namada: &N,
    args: args::Bond,
) -> Result<(), error::Error>
where
    <N::Client as namada::ledger::queries::Client>::Error: std::fmt::Display,
{
    let default_address = args.source.clone().unwrap_or(args.validator.clone());
    submit_reveal_aux(namada, args.tx.clone(), &default_address).await?;

    let (mut tx, signing_data, _fee_unshield_epoch) =
        args.build(namada).await?;
    signing::generate_test_vector(namada, &tx).await?;

    if args.tx.dump_tx {
        tx::dump_tx(namada.io(), &args.tx, tx);
    } else {
        namada.sign(&mut tx, &args.tx, signing_data).await?;

        namada.submit(tx, &args.tx).await?;
    }

    Ok(())
}

pub async fn submit_unbond<'a, N: Namada<'a>>(
    namada: &N,
    args: args::Unbond,
) -> Result<(), error::Error>
where
    <N::Client as namada::ledger::queries::Client>::Error: std::fmt::Display,
{
    let (mut tx, signing_data, _fee_unshield_epoch, latest_withdrawal_pre) =
        args.build(namada).await?;
    signing::generate_test_vector(namada, &tx).await?;

    if args.tx.dump_tx {
        tx::dump_tx(namada.io(), &args.tx, tx);
    } else {
        namada.sign(&mut tx, &args.tx, signing_data).await?;

        namada.submit(tx, &args.tx).await?;

        tx::query_unbonds(namada, args.clone(), latest_withdrawal_pre).await?;
    }

    Ok(())
}

pub async fn submit_withdraw<'a, N: Namada<'a>>(
    namada: &N,
    args: args::Withdraw,
) -> Result<(), error::Error>
where
    <N::Client as namada::ledger::queries::Client>::Error: std::fmt::Display,
{
    let (mut tx, signing_data, _fee_unshield_epoch) =
        args.build(namada).await?;
    signing::generate_test_vector(namada, &tx).await?;

    if args.tx.dump_tx {
        tx::dump_tx(namada.io(), &args.tx, tx);
    } else {
        namada.sign(&mut tx, &args.tx, signing_data).await?;

        namada.submit(tx, &args.tx).await?;
    }

    Ok(())
}

pub async fn submit_redelegate<'a, N: Namada<'a>>(
    namada: &N,
    args: args::Redelegate,
) -> Result<(), error::Error>
where
    <N::Client as namada::ledger::queries::Client>::Error: std::fmt::Display,
{
    let (mut tx, signing_data) = args.build(namada).await?;
    signing::generate_test_vector(namada, &tx).await?;

    if args.tx.dump_tx {
        tx::dump_tx(namada.io(), &args.tx, tx);
    } else {
        namada.sign(&mut tx, &args.tx, signing_data).await?;

        namada.submit(tx, &args.tx).await?;
    }

    Ok(())
}

pub async fn submit_validator_commission_change<'a, N: Namada<'a>>(
    namada: &N,
    args: args::CommissionRateChange,
) -> Result<(), error::Error>
where
    <N::Client as namada::ledger::queries::Client>::Error: std::fmt::Display,
{
    let (mut tx, signing_data, _fee_unshield_epoch) =
        args.build(namada).await?;
    signing::generate_test_vector(namada, &tx).await?;

    if args.tx.dump_tx {
        tx::dump_tx(namada.io(), &args.tx, tx);
    } else {
        namada.sign(&mut tx, &args.tx, signing_data).await?;

        namada.submit(tx, &args.tx).await?;
    }

    Ok(())
}

pub async fn submit_unjail_validator<'a, N: Namada<'a>>(
    namada: &N,
    args: args::TxUnjailValidator,
) -> Result<(), error::Error>
where
    <N::Client as namada::ledger::queries::Client>::Error: std::fmt::Display,
{
    let (mut tx, signing_data, _fee_unshield_epoch) =
        args.build(namada).await?;
    signing::generate_test_vector(namada, &tx).await?;

    if args.tx.dump_tx {
        tx::dump_tx(namada.io(), &args.tx, tx);
    } else {
        namada.sign(&mut tx, &args.tx, signing_data).await?;

        namada.submit(tx, &args.tx).await?;
    }

    Ok(())
}

pub async fn submit_update_steward_commission<'a, N: Namada<'a>>(
    namada: &N,
    args: args::UpdateStewardCommission,
) -> Result<(), error::Error>
where
    <N::Client as namada::ledger::queries::Client>::Error: std::fmt::Display,
{
    let (mut tx, signing_data, _fee_unshield_epoch) =
        args.build(namada).await?;

    signing::generate_test_vector(namada, &tx).await?;

    if args.tx.dump_tx {
        tx::dump_tx(namada.io(), &args.tx, tx);
    } else {
        namada.sign(&mut tx, &args.tx, signing_data).await?;
        namada.submit(tx, &args.tx).await?;
    }

    Ok(())
}

pub async fn submit_resign_steward<'a, N: Namada<'a>>(
    namada: &N,
    args: args::ResignSteward,
) -> Result<(), error::Error>
where
    <N::Client as namada::ledger::queries::Client>::Error: std::fmt::Display,
{
    let (mut tx, signing_data, _epoch) = args.build(namada).await?;

    signing::generate_test_vector(namada, &tx).await?;

    if args.tx.dump_tx {
        tx::dump_tx(namada.io(), &args.tx, tx);
    } else {
        namada.sign(&mut tx, &args.tx, signing_data).await?;
        namada.submit(tx, &args.tx).await?;
    }

    Ok(())
}

/// Save accounts initialized from a tx into the wallet, if any.
pub async fn save_initialized_accounts<'a>(
    namada: &impl Namada<'a>,
    args: &args::Tx,
    initialized_accounts: Vec<Address>,
) {
    tx::save_initialized_accounts(namada, args, initialized_accounts).await
}

/// Broadcast a transaction to be included in the blockchain and checks that
/// the tx has been successfully included into the mempool of a validator
///
/// In the case of errors in any of those stages, an error message is returned
pub async fn broadcast_tx<'a>(
    namada: &impl Namada<'a>,
    to_broadcast: &TxBroadcastData,
) -> Result<Response, error::Error> {
    tx::broadcast_tx(namada, to_broadcast).await
}

/// Broadcast a transaction to be included in the blockchain.
///
/// Checks that
/// 1. The tx has been successfully included into the mempool of a validator
/// 2. The tx with encrypted payload has been included on the blockchain
/// 3. The decrypted payload of the tx has been included on the blockchain.
///
/// In the case of errors in any of those stages, an error message is returned
pub async fn submit_tx<'a>(
    namada: &impl Namada<'a>,
    to_broadcast: TxBroadcastData,
) -> Result<TxResponse, error::Error> {
    tx::submit_tx(namada, to_broadcast).await
}
