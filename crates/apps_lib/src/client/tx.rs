use std::fs::File;
use std::io::Write;

use color_eyre::owo_colors::OwoColorize;
use ledger_namada_rs::{BIP44Path, KeyResponse, NamadaApp, NamadaKeys};
use masp_primitives::sapling::redjubjub::PrivateKey;
use masp_primitives::sapling::{redjubjub, ProofGenerationKey};
use masp_primitives::transaction::components::sapling;
use masp_primitives::transaction::components::sapling::builder::{
    BuildParams, ConvertBuildParams, OutputBuildParams, RngBuildParams,
    SpendBuildParams, StoredBuildParams,
};
use masp_primitives::transaction::components::sapling::fees::InputView;
use masp_primitives::zip32::{
    ExtendedFullViewingKey, ExtendedKey, PseudoExtendedKey,
};
use namada_core::masp::MaspTransaction;
use namada_sdk::address::{Address, ImplicitAddress, MASP};
use namada_sdk::args::TxBecomeValidator;
use namada_sdk::borsh::{BorshDeserialize, BorshSerializeExt};
use namada_sdk::collections::HashMap;
use namada_sdk::governance::cli::onchain::{
    DefaultProposal, PgfFundingProposal, PgfStewardProposal,
};
use namada_sdk::ibc::convert_masp_tx_to_ibc_memo;
use namada_sdk::io::{display_line, edisplay_line, Io};
use namada_sdk::key::*;
use namada_sdk::rpc::{InnerTxResult, TxBroadcastData, TxResponse};
use namada_sdk::state::EPOCH_SWITCH_BLOCKS_DELAY;
use namada_sdk::tx::data::compute_inner_tx_hash;
use namada_sdk::tx::{CompressedAuthorization, Section, Signer, Tx};
use namada_sdk::wallet::alias::{validator_address, validator_consensus_key};
use namada_sdk::wallet::{Wallet, WalletIo};
use namada_sdk::{error, signing, tx, ExtendedViewingKey, Namada};
use rand::rngs::OsRng;
use tokio::sync::RwLock;

use super::rpc;
use crate::cli::{args, safe_exit};
use crate::client::tx::signing::{default_sign, SigningTxData};
use crate::client::tx::tx::ProcessTxResponse;
use crate::config::TendermintMode;
use crate::tendermint_node;
use crate::tendermint_rpc::endpoint::broadcast::tx_sync::Response;
use crate::wallet::{
    gen_validator_keys, read_and_confirm_encryption_password, WalletTransport,
};

// Maximum number of spend description randomness parameters that can be
// generated on the hardware wallet. It is hard to compute the exact required
// number because a given MASP source could be distributed amongst several
// notes.
const MAX_HW_SPEND: usize = 15;
// Maximum number of convert description randomness parameters that can be
// generated on the hardware wallet. It is hard to compute the exact required
// number because the number of conversions that are used depends on the
// protocol's current state.
const MAX_HW_CONVERT: usize = 15;
// Maximum number of output description randomness parameters that can be
// generated on the hardware wallet. It is hard to compute the exact required
// number because the number of outputs depends on the number of dummy outputs
// introduced.
const MAX_HW_OUTPUT: usize = 15;

/// Wrapper around `signing::aux_signing_data` that stores the optional
/// disposable address to the wallet
pub async fn aux_signing_data(
    context: &impl Namada,
    args: &args::Tx,
    owner: Option<Address>,
    default_signer: Option<Address>,
    disposable_signing_key: bool,
) -> Result<signing::SigningTxData, error::Error> {
    let signing_data = signing::aux_signing_data(
        context,
        args,
        owner,
        default_signer,
        vec![],
        disposable_signing_key,
    )
    .await?;

    if disposable_signing_key {
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

pub async fn with_hardware_wallet<'a, U, T>(
    mut tx: Tx,
    pubkey: common::PublicKey,
    parts: signing::Signable,
    (wallet, app): (&RwLock<Wallet<U>>, &NamadaApp<T>),
) -> Result<Tx, error::Error>
where
    U: WalletIo + Clone,
    T: ledger_transport::Exchange + Send + Sync,
    <T as ledger_transport::Exchange>::Error: std::error::Error,
{
    // Obtain derivation path
    let path = wallet
        .read()
        .await
        .find_path_by_pkh(&(&pubkey).into())
        .map_err(|_| {
            error::Error::Other(
                "Unable to find derivation path for key".to_string(),
            )
        })?;
    let path = BIP44Path {
        path: path.to_string(),
    };
    // Now check that the public key at this path in the Ledger
    // matches
    let response_pubkey = app
        .get_address_and_pubkey(&path, false)
        .await
        .map_err(|err| error::Error::Other(err.to_string()))?;
    let response_pubkey =
        common::PublicKey::try_from_slice(&response_pubkey.public_key)
            .map_err(|err| {
                error::Error::Other(format!(
                    "unable to decode public key from hardware wallet: {}",
                    err
                ))
            })?;
    if response_pubkey != pubkey {
        return Err(error::Error::Other(format!(
            "Unrecognized public key fetched from Ledger: {}. Expected {}.",
            response_pubkey, pubkey,
        )));
    }
    // Get the Ledger to sign using our obtained derivation path
    println!(
        "Requesting that hardware wallet sign transaction with transparent \
         key at {}...",
        path.path
    );
    let response = app
        .sign(&path, &tx.serialize_to_vec())
        .await
        .map_err(|err| error::Error::Other(err.to_string()))?;
    // Sign the raw header if that is requested
    if parts == signing::Signable::RawHeader
        || parts == signing::Signable::FeeRawHeader
    {
        let pubkey = common::PublicKey::try_from_slice(&response.pubkey)
            .expect("unable to parse public key from Ledger");
        let signature =
            common::Signature::try_from_slice(&response.raw_signature)
                .expect("unable to parse signature from Ledger");
        // Signatures from the Ledger come back in compressed
        // form
        let compressed = CompressedAuthorization {
            targets: response.raw_indices,
            signer: Signer::PubKeys(vec![pubkey]),
            signatures: [(0, signature)].into(),
        };
        // Expand out the signature before adding it to the
        // transaction
        tx.add_section(Section::Authorization(compressed.expand(&tx)));
    }
    // Sign the fee header if that is requested
    if parts == signing::Signable::FeeRawHeader {
        let pubkey = common::PublicKey::try_from_slice(&response.pubkey)
            .expect("unable to parse public key from Ledger");
        let signature =
            common::Signature::try_from_slice(&response.wrapper_signature)
                .expect("unable to parse signature from Ledger");
        // Signatures from the Ledger come back in compressed
        // form
        let compressed = CompressedAuthorization {
            targets: response.wrapper_indices,
            signer: Signer::PubKeys(vec![pubkey]),
            signatures: [(0, signature)].into(),
        };
        // Expand out the signature before adding it to the
        // transaction
        tx.add_section(Section::Authorization(compressed.expand(&tx)));
    }
    Ok(tx)
}

// Sign the given transaction using a hardware wallet as a backup
pub async fn sign<N: Namada>(
    context: &N,
    tx: &mut Tx,
    args: &args::Tx,
    signing_data: SigningTxData,
) -> Result<(), error::Error> {
    // Setup a reusable context for signing transactions using the Ledger
    if args.use_device {
        let transport = WalletTransport::from_arg(args.device_transport);
        let app = NamadaApp::new(transport);
        let with_hw_data = (context.wallet_lock(), &app);
        // Finally, begin the signing with the Ledger as backup
        context
            .sign(
                tx,
                args,
                signing_data,
                with_hardware_wallet::<N::WalletUtils, _>,
                with_hw_data,
            )
            .await?;
    } else {
        // Otherwise sign without a backup procedure
        context
            .sign(tx, args, signing_data, default_sign, ())
            .await?;
    }
    Ok(())
}

// Build a transaction to reveal the signer of the given transaction.
pub async fn submit_reveal_aux(
    context: &impl Namada,
    args: &args::Tx,
    address: &Address,
) -> Result<Option<(Tx, SigningTxData)>, error::Error> {
    if args.dump_tx || args.dump_wrapper_tx {
        return Ok(None);
    }

    if let Address::Implicit(ImplicitAddress(pkh)) = address {
        let public_key = context
            .wallet_mut()
            .await
            .find_public_key_by_pkh(pkh)
            .map_err(|e| error::Error::Other(e.to_string()))?;

        if tx::is_reveal_pk_needed(context.client(), address).await? {
            display_line!(
                context.io(),
                "Submitting a tx to reveal the public key for address \
                 {address}"
            );
            return Ok(Some(
                tx::build_reveal_pk(context, args, &public_key).await?,
            ));
        }
    }

    Ok(None)
}

async fn batch_opt_reveal_pk_and_submit<N: Namada>(
    namada: &N,
    args: &args::Tx,
    owners: &[&Address],
    mut tx_data: (Tx, SigningTxData),
) -> Result<ProcessTxResponse, error::Error>
where
    <N::Client as namada_sdk::io::Client>::Error: std::fmt::Display,
{
    let mut batched_tx_data = vec![];

    for owner in owners {
        if let Some(reveal_pk_tx_data) =
            submit_reveal_aux(namada, args, owner).await?
        {
            batched_tx_data.push(reveal_pk_tx_data);
        }
    }

    // Since hardware wallets do not yet support batched transactions, use a
    // different logic in order to achieve compatibility
    if args.use_device {
        // Sign each transaction separately
        for (tx, sig_data) in &mut batched_tx_data {
            sign(namada, tx, args, sig_data.clone()).await?;
        }
        sign(namada, &mut tx_data.0, args, tx_data.1).await?;
        // Then submit each transaction separately
        for (tx, _sig_data) in batched_tx_data {
            namada.submit(tx, args).await?;
        }
        // The result of submitting this function's argument is what is returned
        namada.submit(tx_data.0, args).await
    } else {
        // Otherwise complete the batch with this function's argument
        batched_tx_data.push(tx_data);
        let (mut batched_tx, batched_signing_data) =
            namada_sdk::tx::build_batch(batched_tx_data)?;
        // Sign the batch with the union of the signers required for each part
        for sig_data in batched_signing_data {
            sign(namada, &mut batched_tx, args, sig_data).await?;
        }
        // Then finally submit everything in one go
        namada.submit(batched_tx, args).await
    }
}

pub async fn submit_bridge_pool_tx<N: Namada>(
    namada: &N,
    args: args::EthereumBridgePool,
) -> Result<(), error::Error> {
    let bridge_pool_tx_data = args.clone().build(namada).await?;

    if args.tx.dump_tx || args.tx.dump_wrapper_tx {
        tx::dump_tx(namada.io(), &args.tx, bridge_pool_tx_data.0)?;
    } else {
        batch_opt_reveal_pk_and_submit(
            namada,
            &args.tx,
            &[&args.sender],
            bridge_pool_tx_data,
        )
        .await?;
    }

    Ok(())
}

pub async fn submit_custom<N: Namada>(
    namada: &N,
    args: args::TxCustom,
) -> Result<(), error::Error>
where
    <N::Client as namada_sdk::io::Client>::Error: std::fmt::Display,
{
    let (mut tx, signing_data) = args.build(namada).await?;

    if args.tx.dump_tx {
        return tx::dump_tx(namada.io(), &args.tx, tx);
    }
    if args.tx.dump_wrapper_tx {
        // Attach the provided inner signatures to the tx (if any)
        let signatures = args
            .tx
            .signatures
            .iter()
            .map(|bytes| {
                tx::SignatureIndex::try_from_json_bytes(bytes).map_err(|err| {
                    error::Error::Encode(error::EncodingError::Serde(
                        err.to_string(),
                    ))
                })
            })
            .collect::<error::Result<Vec<_>>>()?;
        tx.add_signatures(signatures);

        return tx::dump_tx(namada.io(), &args.tx, tx);
    }

    if let Some(signing_data) = signing_data {
        let owners = args
            .owner
            .map_or_else(Default::default, |owner| vec![owner]);
        let refs: Vec<&Address> = owners.iter().collect();
        batch_opt_reveal_pk_and_submit(
            namada,
            &args.tx,
            &refs,
            (tx, signing_data),
        )
        .await?;
    } else {
        // Just submit without the need for signing
        namada.submit(tx, &args.tx).await?;
    }

    Ok(())
}

pub async fn submit_update_account<N: Namada>(
    namada: &N,
    args: args::TxUpdateAccount,
) -> Result<(), error::Error>
where
    <N::Client as namada_sdk::io::Client>::Error: std::fmt::Display,
{
    let (mut tx, signing_data) = args.build(namada).await?;

    if args.tx.dump_tx || args.tx.dump_wrapper_tx {
        tx::dump_tx(namada.io(), &args.tx, tx)?;
    } else {
        sign(namada, &mut tx, &args.tx, signing_data).await?;

        namada.submit(tx, &args.tx).await?;
    }

    Ok(())
}

pub async fn submit_init_account<N: Namada>(
    namada: &N,
    args: args::TxInitAccount,
) -> Result<Option<Address>, error::Error>
where
    <N::Client as namada_sdk::io::Client>::Error: std::fmt::Display,
{
    let (mut tx, signing_data) = tx::build_init_account(namada, &args).await?;

    if args.tx.dump_tx || args.tx.dump_wrapper_tx {
        tx::dump_tx(namada.io(), &args.tx, tx)?;
    } else {
        sign(namada, &mut tx, &args.tx, signing_data).await?;

        let cmt = tx.first_commitments().unwrap().to_owned();
        let wrapper_hash = tx.wrapper_hash();
        let response = namada.submit(tx, &args.tx).await?;
        if let Some(result) =
            response.is_applied_and_valid(wrapper_hash.as_ref(), &cmt)
        {
            return Ok(result.initialized_accounts.first().cloned());
        }
    }

    Ok(None)
}

pub async fn submit_change_consensus_key(
    namada: &impl Namada,
    args: args::ConsensusKeyChange,
) -> Result<(), error::Error> {
    let validator = args.validator;
    let consensus_key = args.consensus_key;

    // Determine the alias for the new key
    let mut wallet = namada.wallet_mut().await;
    let alias = wallet.find_alias(&validator).cloned();
    let base_consensus_key_alias = alias
        .map(|al| validator_consensus_key(&al))
        .unwrap_or_else(|| {
            validator_consensus_key(&validator.to_string().into())
        });
    let mut consensus_key_alias = base_consensus_key_alias.to_string();
    let all_keys = wallet.get_secret_keys();
    let mut key_counter = 0;
    while all_keys.contains_key(&consensus_key_alias) {
        key_counter += 1;
        consensus_key_alias =
            format!("{base_consensus_key_alias}-{key_counter}");
    }

    // Check the given key or generate a new one
    let new_key = consensus_key
        .map(|key| match key {
            common::PublicKey::Ed25519(_) => key,
            common::PublicKey::Secp256k1(_) => {
                edisplay_line!(
                    namada.io(),
                    "Consensus key can only be ed25519"
                );
                safe_exit(1)
            }
        })
        .unwrap_or_else(|| {
            display_line!(namada.io(), "Generating new consensus key...");
            let password =
                read_and_confirm_encryption_password(args.unsafe_dont_encrypt);
            wallet
                .gen_store_secret_key(
                    // Note that TM only allows ed25519 for consensus key
                    SchemeType::Ed25519,
                    Some(consensus_key_alias.clone()),
                    args.tx.wallet_alias_force,
                    password,
                    &mut OsRng,
                )
                .expect("Key generation should not fail.")
                .1
                .ref_to()
        });

    // To avoid wallet deadlocks in following operations
    drop(wallet);

    let args = args::ConsensusKeyChange {
        validator: validator.clone(),
        consensus_key: Some(new_key.clone()),
        ..args
    };

    let (mut tx, signing_data) = args.build(namada).await?;

    if args.tx.dump_tx || args.tx.dump_wrapper_tx {
        tx::dump_tx(namada.io(), &args.tx, tx)?
    } else {
        sign(namada, &mut tx, &args.tx, signing_data).await?;
        let cmt = tx.first_commitments().unwrap().to_owned();
        let wrapper_hash = tx.wrapper_hash();
        let resp = namada.submit(tx, &args.tx).await?;

        if !(args.tx.dry_run || args.tx.dry_run_wrapper) {
            if resp
                .is_applied_and_valid(wrapper_hash.as_ref(), &cmt)
                .is_some()
            {
                namada.wallet_mut().await.save().unwrap_or_else(|err| {
                    edisplay_line!(namada.io(), "{}", err)
                });

                display_line!(
                    namada.io(),
                    "New consensus key stored with alias \
                     \"{consensus_key_alias}\". It will become active \
                     {EPOCH_SWITCH_BLOCKS_DELAY} blocks before the start of \
                     the pipeline epoch relative to the current epoch \
                     (current epoch + pipeline offset), at which point you \
                     will need to give the new key to CometBFT in order to be \
                     able to sign with it in consensus.",
                );
            }
        } else {
            display_line!(
                namada.io(),
                "Transaction dry run. No new consensus key has been saved."
            );
        }
    }
    Ok(())
}

pub async fn submit_become_validator(
    namada: &impl Namada,
    config: &mut crate::config::Config,
    args: args::TxBecomeValidator,
) -> Result<(), error::Error> {
    let alias = args
        .tx
        .initialized_account_alias
        .as_ref()
        .cloned()
        .unwrap_or_else(|| "validator".to_string());

    let validator_key_alias = format!("{}-key", alias);
    let consensus_key_alias = validator_consensus_key(&alias.clone().into());
    let protocol_key_alias = format!("{}-protocol-key", alias);
    let eth_hot_key_alias = format!("{}-eth-hot-key", alias);
    let eth_cold_key_alias = format!("{}-eth-cold-key", alias);
    let address_alias = validator_address(&alias.clone().into());

    let mut wallet = namada.wallet_mut().await;
    let consensus_key = args
        .consensus_key
        .clone()
        .map(|key| match key {
            common::PublicKey::Ed25519(_) => key,
            common::PublicKey::Secp256k1(_) => {
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
                read_and_confirm_encryption_password(args.unsafe_dont_encrypt);
            wallet
                .gen_store_secret_key(
                    // Note that TM only allows ed25519 for consensus key
                    SchemeType::Ed25519,
                    Some(consensus_key_alias.clone().into()),
                    args.tx.wallet_alias_force,
                    password,
                    &mut OsRng,
                )
                .expect("Key generation should not fail.")
                .1
                .ref_to()
        });

    let eth_cold_pk = args
        .eth_cold_key
        .clone()
        .map(|key| match key {
            common::PublicKey::Secp256k1(_) => key,
            common::PublicKey::Ed25519(_) => {
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
                read_and_confirm_encryption_password(args.unsafe_dont_encrypt);
            wallet
                .gen_store_secret_key(
                    // Note that ETH only allows secp256k1
                    SchemeType::Secp256k1,
                    Some(eth_cold_key_alias.clone()),
                    args.tx.wallet_alias_force,
                    password,
                    &mut OsRng,
                )
                .expect("Key generation should not fail.")
                .1
                .ref_to()
        });

    let eth_hot_pk = args
        .eth_hot_key
        .clone()
        .map(|key| match key {
            common::PublicKey::Secp256k1(_) => key,
            common::PublicKey::Ed25519(_) => {
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
                read_and_confirm_encryption_password(args.unsafe_dont_encrypt);
            wallet
                .gen_store_secret_key(
                    // Note that ETH only allows secp256k1
                    SchemeType::Secp256k1,
                    Some(eth_hot_key_alias.clone()),
                    args.tx.wallet_alias_force,
                    password,
                    &mut OsRng,
                )
                .expect("Key generation should not fail.")
                .1
                .ref_to()
        });
    // To avoid wallet deadlocks in following operations
    drop(wallet);

    if args.protocol_key.is_none() {
        display_line!(namada.io(), "Generating protocol signing key...");
    }

    // Generate the validator keys
    let validator_keys = gen_validator_keys(
        &mut *namada.wallet_mut().await,
        Some(eth_hot_pk.clone()),
        args.protocol_key.clone(),
        args.scheme,
    )
    .unwrap();
    let protocol_sk = validator_keys.get_protocol_keypair();
    let protocol_key = protocol_sk.to_public();

    let args = TxBecomeValidator {
        consensus_key: Some(consensus_key.clone()),
        eth_cold_key: Some(eth_cold_pk),
        eth_hot_key: Some(eth_hot_pk),
        protocol_key: Some(protocol_key),
        ..args
    };

    // Store the protocol key in the wallet so that we can sign the tx with it
    // to verify ownership
    display_line!(namada.io(), "Storing protocol key in the wallet...");
    let password =
        read_and_confirm_encryption_password(args.unsafe_dont_encrypt);
    namada
        .wallet_mut()
        .await
        .insert_keypair(
            protocol_key_alias,
            args.tx.wallet_alias_force,
            protocol_sk.clone(),
            password,
            None,
            None,
        )
        .ok_or(error::Error::Other(String::from(
            "Failed to store the keypair.",
        )))?;

    let (mut tx, signing_data) = args.build(namada).await?;

    if args.tx.dump_tx || args.tx.dump_wrapper_tx {
        tx::dump_tx(namada.io(), &args.tx, tx)?;
    } else {
        sign(namada, &mut tx, &args.tx, signing_data).await?;
        let cmt = tx.first_commitments().unwrap().to_owned();
        let wrapper_hash = tx.wrapper_hash();
        let resp = namada.submit(tx, &args.tx).await?;

        if args.tx.dry_run || args.tx.dry_run_wrapper {
            display_line!(
                namada.io(),
                "Transaction dry run. No key or addresses have been saved."
            );
            safe_exit(0)
        }

        if resp
            .is_applied_and_valid(wrapper_hash.as_ref(), &cmt)
            .is_none()
        {
            return Err(error::Error::Tx(error::TxSubmitError::Other(
                "Transaction failed. No key or addresses have been saved."
                    .to_string(),
            )));
        }

        // add validator address and keys to the wallet
        let mut wallet = namada.wallet_mut().await;
        wallet.insert_address(
            address_alias.normalize(),
            args.address.clone(),
            false,
        );
        wallet.add_validator_data(args.address.clone(), validator_keys);
        wallet
            .save()
            .unwrap_or_else(|err| edisplay_line!(namada.io(), "{}", err));

        let tendermint_home = config.ledger.cometbft_dir();
        tendermint_node::write_validator_key(
            &tendermint_home,
            &wallet
                .find_key_by_pk(&consensus_key, None)
                .expect("unable to find consensus key pair in the wallet"),
        )
        .unwrap();
        // To avoid wallet deadlocks in following operations
        drop(wallet);
        tendermint_node::write_validator_state(tendermint_home).unwrap();

        // Write Namada config stuff or figure out how to do the above
        // tendermint_node things two epochs in the future!!!
        config.ledger.shell.tendermint_mode = TendermintMode::Validator;
        config
            .write(&config.ledger.shell.base_dir, &config.ledger.chain_id, true)
            .unwrap();

        let pos_params = rpc::query_pos_parameters(namada.client()).await;

        display_line!(namada.io(), "");
        display_line!(
            namada.io(),
            "The keys for validator \"{alias}\" were stored in the wallet:"
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
            "Your validator address {} has been stored in the wallet with \
             alias \"{}\".",
            args.address,
            address_alias
        );
        display_line!(
            namada.io(),
            "The ledger node has been setup to use this validator's address \
             and consensus key."
        );
        display_line!(
            namada.io(),
            "Your validator will be active in {} epochs. Be sure to restart \
             your node for the changes to take effect!",
            pos_params.pipeline_len
        );
    }
    Ok(())
}

pub async fn submit_init_validator(
    namada: &impl Namada,
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
        email,
        website,
        description,
        discord_handle,
        avatar,
        name,
        validator_vp_code_path,
        unsafe_dont_encrypt,
        tx_init_account_code_path,
        tx_become_validator_code_path,
    }: args::TxInitValidator,
) -> Result<(), error::Error> {
    let address = submit_init_account(
        namada,
        args::TxInitAccount {
            tx: tx_args.clone(),
            vp_code_path: validator_vp_code_path,
            tx_code_path: tx_init_account_code_path,
            public_keys: account_keys,
            threshold,
        },
    )
    .await?;

    if tx_args.dry_run || tx_args.dry_run_wrapper {
        eprintln!(
            "Cannot proceed to become validator in dry-run as no account has \
             been created"
        );
        safe_exit(1)
    }
    let address = address.unwrap_or_else(|| {
        eprintln!(
            "Something went wrong with transaction to initialize an account \
             as no address has been created. Cannot proceed to become \
             validator."
        );
        safe_exit(1);
    });

    submit_become_validator(
        namada,
        config,
        args::TxBecomeValidator {
            tx: tx_args,
            address,
            scheme,
            consensus_key,
            eth_cold_key,
            eth_hot_key,
            protocol_key,
            commission_rate,
            max_commission_rate_change,
            email,
            description,
            website,
            discord_handle,
            avatar,
            name,
            tx_code_path: tx_become_validator_code_path,
            unsafe_dont_encrypt,
        },
    )
    .await
}

pub async fn submit_transparent_transfer(
    namada: &impl Namada,
    args: args::TxTransparentTransfer,
) -> Result<(), error::Error> {
    if args.data.len() > 1 {
        // TODO(namada#3379): Vectorized transfers are not yet supported in the
        // CLI
        return Err(error::Error::Other(
            "Unexpected vectorized transparent transfer".to_string(),
        ));
    }

    let transfer_data = args.clone().build(namada).await?;

    if args.tx.dump_tx || args.tx.dump_wrapper_tx {
        tx::dump_tx(namada.io(), &args.tx, transfer_data.0)?;
    } else {
        let reveal_pks: Vec<_> =
            args.data.iter().map(|datum| &datum.source).collect();
        batch_opt_reveal_pk_and_submit(
            namada,
            &args.tx,
            &reveal_pks,
            transfer_data,
        )
        .await?;
    }

    Ok(())
}

// A mapper that replaces authorization signatures with those in a built-in map
struct MapSaplingSigAuth(
    HashMap<usize, <sapling::Authorized as sapling::Authorization>::AuthSig>,
);

impl sapling::MapAuth<sapling::Authorized, sapling::Authorized>
    for MapSaplingSigAuth
{
    fn map_proof(
        &self,
        p: <sapling::Authorized as sapling::Authorization>::Proof,
        _pos: usize,
    ) -> <sapling::Authorized as sapling::Authorization>::Proof {
        p
    }

    fn map_auth_sig(
        &self,
        s: <sapling::Authorized as sapling::Authorization>::AuthSig,
        pos: usize,
    ) -> <sapling::Authorized as sapling::Authorization>::AuthSig {
        self.0.get(&pos).cloned().unwrap_or(s)
    }

    fn map_authorization(&self, a: sapling::Authorized) -> sapling::Authorized {
        a
    }
}

// Identify the viewing keys in the given transaction for which we do not
// possess spending keys in the software wallet, and augment them with a proof
// generation key from the hardware wallet. Returns a mapping from viewing keys
// to corresponding ZIP 32 paths in the hardware wallet. This function errors
// out if any ZIP 32 path that it handles maps to a different viewing key than
// it does on the software client.
async fn augment_masp_hardware_keys(
    namada: &impl Namada,
    args: &args::Tx,
    sources: impl Iterator<Item = &mut PseudoExtendedKey>,
) -> Result<HashMap<String, ExtendedViewingKey>, error::Error> {
    // Records the shielded keys that are on the hardware wallet
    let mut shielded_hw_keys = HashMap::new();
    // Construct the build parameters that parameterized the Transaction
    // authorizations
    if args.use_device {
        let transport = WalletTransport::from_arg(args.device_transport);
        let app = NamadaApp::new(transport);
        let wallet = namada.wallet().await;
        // Augment the pseudo spending key with a proof authorization key
        for source in sources {
            // Only attempt an augmentation if proof authorization is not there
            if source.to_spending_key().is_none() {
                // First find the derivation path corresponding to this viewing
                // key
                let viewing_key =
                    ExtendedViewingKey::from(source.to_viewing_key());
                let path = wallet
                    .find_path_by_viewing_key(&viewing_key)
                    .map_err(|err| {
                        error::Error::Other(format!(
                            "Unable to find derivation path from the wallet \
                             for viewing key {}. Error: {}",
                            viewing_key, err,
                        ))
                    })?;
                let path = BIP44Path {
                    path: path.to_string(),
                };
                // Then confirm that the viewing key at this path in the
                // hardware wallet matches the viewing key in this pseudo
                // spending key
                println!(
                    "Requesting viewing key at {} from hardware wallet...",
                    path.path
                );
                let response = app
                    .retrieve_keys(&path, NamadaKeys::ViewKey, true)
                    .await
                    .map_err(|err| {
                        error::Error::Other(format!(
                            "Unable to obtain viewing key from the hardware \
                             wallet at path {}. Error: {}",
                            path.path, err,
                        ))
                    })?;
                let KeyResponse::ViewKey(response_key) = response else {
                    return Err(error::Error::Other(
                        "Unexpected response from Ledger".to_string(),
                    ));
                };
                let xfvk =
                    ExtendedFullViewingKey::try_from_slice(&response_key.xfvk)
                        .expect(
                            "unable to decode extended full viewing key from \
                             the hardware wallet",
                        );
                if ExtendedFullViewingKey::from(viewing_key) != xfvk {
                    return Err(error::Error::Other(format!(
                        "Unexpected viewing key response from Ledger: {}",
                        ExtendedViewingKey::from(xfvk),
                    )));
                }
                // Then obtain the proof authorization key at this path in the
                // hardware wallet
                let response = app
                    .retrieve_keys(&path, NamadaKeys::ProofGenerationKey, false)
                    .await
                    .map_err(|err| {
                        error::Error::Other(format!(
                            "Unable to obtain proof generation key from the \
                             hardware wallet for viewing key {}. Error: {}",
                            viewing_key, err,
                        ))
                    })?;
                let KeyResponse::ProofGenKey(response_key) = response else {
                    return Err(error::Error::Other(
                        "Unexpected response from Ledger".to_string(),
                    ));
                };
                let pgk = ProofGenerationKey::try_from_slice(
                    &[response_key.ak, response_key.nsk].concat(),
                )
                .map_err(|err| {
                    error::Error::Other(format!(
                        "Unexpected proof generation key in response from the \
                         hardware wallet: {}.",
                        err,
                    ))
                })?;
                // Augment the pseudo spending key
                source.augment_proof_generation_key(pgk).map_err(|_| {
                    error::Error::Other(
                        "Proof generation key in response from the hardware \
                         wallet does not correspond to stored viewing key."
                            .to_string(),
                    )
                })?;
                // Finally, augment an incorrect spend authorization key just to
                // make sure that the Transaction is built.
                source.augment_spend_authorizing_key_unchecked(PrivateKey(
                    jubjub::Fr::default(),
                ));
                shielded_hw_keys.insert(path.path, viewing_key);
            }
        }
        Ok(shielded_hw_keys)
    } else {
        Ok(HashMap::new())
    }
}

// If the hardware wallet is beig used, use it to generate the random build
// parameters for the spend, convert, and output descriptions.
async fn generate_masp_build_params(
    spend_len: usize,
    convert_len: usize,
    output_len: usize,
    args: &args::Tx,
) -> Result<Box<dyn BuildParams>, error::Error> {
    // Construct the build parameters that parameterized the Transaction
    // authorizations
    if args.use_device {
        let transport = WalletTransport::from_arg(args.device_transport);
        let app = NamadaApp::new(transport);
        // Clear hardware wallet randomness buffers
        app.clean_randomness_buffers().await.map_err(|err| {
            error::Error::Other(format!(
                "Unable to clear randomness buffer. Error: {}",
                err,
            ))
        })?;
        // Get randomness to aid in construction of various descriptors
        let mut bparams = StoredBuildParams::default();
        for _ in 0..spend_len {
            let spend_randomness = app
                .get_spend_randomness()
                .await
                .map_err(|err| error::Error::Other(err.to_string()))?;
            bparams.spend_params.push(SpendBuildParams {
                rcv: jubjub::Fr::from_bytes(&spend_randomness.rcv).unwrap(),
                alpha: jubjub::Fr::from_bytes(&spend_randomness.alpha).unwrap(),
            });
        }
        for _ in 0..convert_len {
            let convert_randomness = app
                .get_convert_randomness()
                .await
                .map_err(|err| error::Error::Other(err.to_string()))?;
            bparams.convert_params.push(ConvertBuildParams {
                rcv: jubjub::Fr::from_bytes(&convert_randomness.rcv).unwrap(),
            });
        }
        for _ in 0..output_len {
            let output_randomness = app
                .get_output_randomness()
                .await
                .map_err(|err| error::Error::Other(err.to_string()))?;
            bparams.output_params.push(OutputBuildParams {
                rcv: jubjub::Fr::from_bytes(&output_randomness.rcv).unwrap(),
                rseed: output_randomness.rcm,
                ..OutputBuildParams::default()
            });
        }
        Ok(Box::new(bparams))
    } else {
        Ok(Box::new(RngBuildParams::new(OsRng)))
    }
}

// Sign the given transaction's MASP component using signatures produced by the
// hardware wallet. This function takes the list of spending keys that are
// hosted on the hardware wallet.
async fn masp_sign(
    tx: &mut Tx,
    args: &args::Tx,
    signing_data: &SigningTxData,
    shielded_hw_keys: HashMap<String, ExtendedViewingKey>,
) -> Result<(), error::Error> {
    // Get the MASP section that is the target of our signing
    if let Some(shielded_hash) = signing_data.shielded_hash {
        let mut masp_tx = tx
            .get_masp_section(&shielded_hash)
            .expect("Expected to find the indicated MASP Transaction")
            .clone();

        let masp_builder = tx
            .get_masp_builder(&shielded_hash)
            .expect("Expected to find the indicated MASP Builder");

        // Reverse the spend metadata to enable looking up construction
        // material
        let sapling_inputs = masp_builder.builder.sapling_inputs();
        let mut descriptor_map = vec![0; sapling_inputs.len()];
        for i in 0.. {
            if let Some(pos) = masp_builder.metadata.spend_index(i) {
                descriptor_map[pos] = i;
            } else {
                break;
            };
        }
        // Sign the MASP Transaction using each relevant key in the
        // hardware wallet
        let mut app = None;
        for (path, vk) in shielded_hw_keys {
            // Initialize the Ledger app interface if it is uninitialized
            let app = app.get_or_insert_with(|| {
                NamadaApp::new(WalletTransport::from_arg(args.device_transport))
            });
            // Sign the MASP Transaction using the current viewing key
            let path = BIP44Path {
                path: path.to_string(),
            };
            println!(
                "Requesting that hardware wallet sign shielded transfer with \
                 spending key at {}...",
                path.path
            );
            app.sign_masp_spends(&path, &tx.serialize_to_vec())
                .await
                .map_err(|err| error::Error::Other(err.to_string()))?;
            println!("sign_masp_spends done");
            // Now prepare a new list of authorizations based on hardware
            // wallet responses
            let mut authorizations = HashMap::new();
            for (tx_pos, builder_pos) in descriptor_map.iter().enumerate() {
                // Read the next spend authorization signature from the
                // hardware wallet
                let response = app
                    .get_spend_signature()
                    .await
                    .map_err(|err| error::Error::Other(err.to_string()))?;
                let signature = redjubjub::Signature::try_from_slice(
                    &[response.rbar, response.sbar].concat(),
                )
                .map_err(|err| {
                    error::Error::Other(format!(
                        "Unexpected spend authorization key in response from \
                         the hardware wallet: {}.",
                        err,
                    ))
                })?;
                if *sapling_inputs[*builder_pos].key()
                    == ExtendedFullViewingKey::from(vk)
                {
                    // If this descriptor was produced by the current
                    // viewing key (which comes from the hardware wallet),
                    // then use the authorization from the hardware wallet
                    authorizations.insert(tx_pos, signature);
                }
            }
            // Finally, patch the MASP Transaction with the fetched spend
            // authorization signature
            masp_tx = (*masp_tx)
                .clone()
                .map_authorization::<masp_primitives::transaction::Authorized>(
                    (),
                    MapSaplingSigAuth(authorizations),
                )
                .freeze()
                .map_err(|err| {
                    error::Error::Other(format!(
                        "Unable to apply hardware walleet sourced \
                         authorization signatures to the transaction being \
                         constructed: {}.",
                        err,
                    ))
                })?;
        }
        tx.remove_masp_section(&shielded_hash);
        tx.add_section(Section::MaspTx(masp_tx));
    }
    Ok(())
}

#[tokio::test]
pub async fn check_unshield_transfer() {
    use namada_sdk::token::masp::{WalletMap, NETWORK, testing::MockTxProver};
    use namada_sdk::token::Transfer;
    use masp_primitives::transaction::components::U64Sum;
    use masp_primitives::transaction::fees::fixed::FeeRule;
    use namada_sdk::ExtendedSpendingKey;
    use std::sync::Mutex;
    use std::marker::PhantomData;
    use rand::rngs::StdRng;
    use rand::SeedableRng;
    use std::str::FromStr;
    let tx_bytes = data_encoding::HEXLOWER.decode(b"1e000000696e746567726174696f6e2d746573742e663363313338333830303363650123000000323032352d30312d32335432303a32363a33312e3039313535383736392b30303a303023000000323032352d30312d32335431393a32363a33312e3039313536363433342b30303a30300100000062c9872a7022e614d273be77b18a538ebfaa4a770511c2705e18b87120601514de60311f50736b2229cf2e6e2eaab50ea066150d956afccf5357974851de35cd000000000000000000000000000000000000000000000000000000000000000000010a0000000000000000000000000000000000000000000000000000000000000006006d3f54c911160b0084c247726067ecbbb3cc858d007c38e56ae405489d2615b7a2de3d70fcb7d916f5f5451c5df06d542a5f6da8d160ea0000000000000400000004020000000a27a726a675ffe900000000540e00000001d76005782fa1af6c4810d98fff2ca0259183b23ea5b23a81a0a83bdd8648626e00943577000000001da608100dfd8c5d95437aa60b557ead1631d58b034f6f2c242b6596475719bcb4a28e7aa687857fae56a480e95e662ae0720bf255fe9b8df983a7869ab119e5cf4dfe263a499da7d10e76caa4b7a7a43ac3fdf21df066882d487d9fd5b3377333afa025b52930840b08ec21ae1d3fb654d3df6b4d17a8a66df739f7829af3ea337352c1db045da376cfb4e2d9bf4c882970f8b88f4939898735aee9cdd4b1e141b982799c43178c47406ecc91734ba541ea496f26a05cd1a448f3a362d89ad10eb0b8a89d3446026208c2000d02e92adf3ce091e43236938e3c95cc6033cd2d50df2ef88b25feec0799672dbd84aa0e8685750ce55be764429a9a1f5f2d02b8b71569713038f7bef8f38d96a8e485b1758d045b2bdf75fc1d8215240e86aad934f14b9c50f89636f9d4f04e574c80fbc4b146a81303e50cf97e748a26e319167b24c96d8a6d9e0d2c8babd66bb6180af3268b3c7e825a71321add49bf196834cca3b9e8620b962412dfb91fa9516e3e1e5576ed4454daff234f6465dc84b2b9bcf7104b631121d478ed68b914d09fc50327517f28e902225e4f024679c410dbb0cba78661a84f5a81f973a120f69ada199a46e5d5ced8c9557597a5c73f90502ceebba764a52d0aea93c26287bb041ed600b5e0338f02d3629ed50f8c2ec7681cbfb2b036f06d1549700a53332b4ae01f4088ec8eb65c22a6772e6b1f963303d50adb768bbd6d60ccca6294c7bb06c9f53d3f5f5d241ec28dec2c193a3e938126547d3352213d8a2d88530dd5c382d64c12508f7540a9a03d3d9d87b89b01a434a48bacccc74bb1e9c6b56e0be00199ebf24c417b99ed01707cae2887c147d5f7fc1a2906d2285eacf714f4bcaff9cac1807c2cb5d41534aa91a24cb846ebf8ce1a4c63fbe5fd4d1820a863eddf74f7d009db9a4669e0a75c7a0db9dca85ac4479a0e8923b700142c8044750c069af429ef73f1701f7fb2a66f2bafd5cd5e982cdb99e398889dffb8fca5a2c2789af5852c65c1f8ceff6d9453a827325434d1c8a975bd6696ee83b4fa262916d9af8a081ef2891bf2b7a6540a8343e73b6261a74708df136c7720ed8ba45504fbd09ecf6abf7c36c01e950aabf09a9dfe0294ff8144c8d04cc8592da9670e02758bf400585dad10577ea9cba74ec4e66a424b37fd96b562a243a868a7519e7dd222aa04a2038b77cc9b9e40d5dd65360173ed809e8a22d3e0aca20563d3276ba60576d73a8a0ee53428339ec3cb6a8411a5b7d524d51a7af04d7ef648633b083b259e31bd3c99d08a7ed62e87f90cb897d48eda8c624a63824944837966d2de271b56636de18ab9ba22d172ffda0e81f443689277015464bf989aa1ea966d70e9ac8b99207a4d51a56d42d3aff5926d7cfd765f9a55f78b0914a9d87f60d05a0576fc6cdd1950592f7a9ef9d6a1bd2897d9ac38593f251bd6c63586a4876e95521062eb27bc41899ac9a03138d7060a513b318dc0a3b52091e8e7c074198400580faf4b8908470f7d9631818c32af36e4ce6df3e93f848e3bd0a6c599070bb541bfc648afc776173aacf52c77178a441e00141c924ff4c280983dadc106b576b335be277dace5d0428a70bdee35bf2583eff407fb62e2848ef60a358f34098f08bf93336843a87760e9cfc0c85e245b185817d8b01ab142094eca7fdf1fd0c4e062355fcced182d4d74a355281a4df0052c9cee475dffa8e6f8f3787c98ae0363cc61b0e089a0a3bae47148db6ca5337efb921c1e1754e8b4c3dc1e150e73a46e34b5fdab4e5e843cac7aa776687109402e73b0a4773e9f6ea8081bd783606693ca4412d96e4f4f97afc67257c98a2dffa731adb9095dae038d6940930e739296409240e010f3b328c8545abc224ce85e96c59803f92cb9fdfe6417b206f03aadf26d2101e080d16562d81806f0e65e083439057eafba654744fcd7e611d2419331b6c6411e6e95ed14f8838a0750273894c1cfadca674ab16f8436ad74d3c453a60fd407085a90c832db59073bd86e521cef370a6cd7aa104da8a4a8c571f911f9bc60657d1b70683b7671769f98f3ce0c7fdff60120e70bb4beb21a6c27e1cfbbfebf1a795ef5aed88c8b047d5bd12acc6f88683981ad31d702565fc760f75bae53e5b080b364fda318dafdf7fb1056bbf9ae94e5e112968fb49b91fa40edf35db4a71926fc4848dbd6fa5fb550933beda355b2d197aa33ea8fc7fb6b9a1e35a2eb8671d8d3eea71d6d84079c15c8e628d3feb1d16cf0a5face23d0226b898cedf52dd53da472b51991addb10bc153cd1a4ed4aab5f6dcf815aacb29e00cff65830e6a2e863ea43a94cade4c11e6124a6cb1b46f9cca3f20283dae41c6288a0213095c340f33784709fbb6eb4e3869a8bdc901e915fab49f6c3d671ee631839fba4bb7436dfcbf79aaef786d645ce0371559fbc90e9a4dc592f8f57ae9f3106f9611725eab9731a14df89ec1a8e4c0eeec624a3e0ed518f03df0efe1e880a960a2fb8db78478dc1da7953d20bd51f72853f41249a41d2fb49463bab7db1730dfcce62cf5099ed18483186c8e7787ebdaa8a35b517f67788f22226049c233ba3b74db8129b1c77874e0f7276a02546a37e637c6455e0a977d64fe57e2dd69910cd4a80ba21172099c38a6f0d133ed811ff4c5f20e79d2a42dfaa1318a2e301e0f0a544b19644725644b58e317628a48e62148e6ca4959bf3144a489b82c324d27888fde212fe5a23a57ca4da7e65c6c77164dbaea05f5a9ab141f36bcc967230c8f320f04c0b14dcbafe3f5a96eb0ad7a801d76005782fa1af6c4810d98fff2ca0259183b23ea5b23a81a0a83bdd8648626e00943577000000000000000000000000164223540e9f3604a4e8f8e2a1f0d3bfe32640f73c7b9aebe0286c801871b709173bb5b5ddb51cfe02e14aaba9a0dbe6099ec0cacf49fe165655166b09526d2e97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb897f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb897f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb897f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb4e0de20a3a2cf1926acd00a995b818a5bc42dd3149774381c80d123840cebe3bf2a23c0df45c07aad35b40e76f1dcad51c8ec07619c00f6bf3b549d3edf51604662f85897c51a1054c5f06bb474ae763bca819f803077feec40cfb995373870229c468c842355ca7bf4885a87b505e96c65fb3b3f42988c251d813100c45ec01a47cb1f9ad36586da0ff9ed51ce99e84846f0170b550d82f1e0942085e87f53372aeb7b2e847b9e6759d050f78fd89dc3247ab1182042c5b563aa8f83a17cc0097f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb897f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb897f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb897f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb897f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb897f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb8979d4e0e6d5a6c79e82c1514198cd383a9753dc37f2b6032f3700e6ae552cd0ba11b6beeae034284b0ca0bd162fd8a7697efffbbb1297fd4493b17d4a7fa403051851abe9b403ecf912a68fe29942e1dc6ab95e7faecf3fbc466f679fd73ae22205000000000e797496138ebe935066f9ab58c6950cda45da030800010300000000000000000e797496138ebe935066f9ab58c6950cda45da030800010400000000000000006d3f54c911160b0084c247726067ecbbb3cc858d0600010500000000000000000e797496138ebe935066f9ab58c6950cda45da030800010500000000000000006d3f54c911160b0084c247726067ecbbb3cc858d06000100000000000000000300000002000000000000000100000000000000000000000000000003000000010000000000000002000000000000000000000000000000010000000000000000000000400e0000540e00000000000001000000d76005782fa1af6c4810d98fff2ca0259183b23ea5b23a81a0a83bdd8648626e00943577000000001da608100dfd8c5d95437aa60b557ead1631d58b01164223540e9f3604a4e8f8e2a1f0d3bfe32640f73c7b9aebe0286c801871b709400e000001d76005782fa1af6c4810d98fff2ca0259183b23ea5b23a81a0a83bdd8648626e0094357700000000000000000000000001173bb5b5ddb51cfe02e14aaba9a0dbe6099ec0cacf49fe165655166b09526d2e0300000003bc4834ed020000804c0f3ddf65a15f86e4bad5214a97cab34339fcc1f12ed6a7d3f2e41af052584ea01b3b0d4047c0dc74ae4c433a1c374d66851fd3dd30f7cc10870b45c5a8c0c8f3ef8e52cee9d1b303cc3b03dc8f71f592ba5e641e7620fe7d52fd6dd64a13342bd03f1b3b0ef4a844e475666c848b98e53d6e7f9f92f022770da543d1f370d80b052443197255c12e5bbacab7ea57bc7d86c9378b2f21973e7afadf1f603d0f8e74f310b388b3e744f46bcffc144a76f1deb9d92ef1ec846c26d52e22624a1bef50023f09cc1c7181e09e0027b9290000000038de7e8e227df9f26744b9a64e0413efeafde7214bb38bc3e795fdd1fcb9d691dfda5c460bc0c759072d980fb2280b2a7bd274751aa85d004cbf403fe138825202a6b1f4923cc92878442973e325cfb17ae4d22a77547c9e3ec639f9d0fcf232912020de43f9cb72ec5b01c93aff1981a6cb7765b3e0c60ecdd4f0ddc1f1dda252ff0e20ad15f9b7057e4431f40b17d3cc76194d8339b1ddd9d80b20352002634663642e2089fd643bbfeef5b486e4e29e1c99d72c29944791c32fc225396b59318681b633208ef64e2cbb03d5af593244b253abc3e94db3b9150596e17303940d4eb2d5781a20a5461d4e8bd352703204beb6277e50a2c27e7779f7ab98fd45ceb0bba5c1b901203b52fb113249110b4566887d79a9693c3be69572a5b90b690702066e97ef155c204b07ba48cb4a793c01dfeb6392195b6493f3ceed52b5cea7df7279220e967e47204147f5d495d644e9c246093bdba51a94d44de39bb435f3410b52969570babe6d20b522e12ee1a1aa449be27411bbf4f8bdf90a8a816b7144f28991fa307644541b20d88bbcd3447046ef164ce336bdb9d6d29f4367d2f8aa7d39644e87c9c1ecca05202d7708b49a8ab745c2f51f638649c6a455842a6f4e040aae4d9885546337245920897423682b6d8f56fce75bf9c4a7f70f35dfa7386e554e7c561a62a835c3a3662049c2d8eff3e9c0a5a2017de57ab4e2c12eea2cf06228127f26580f4fa9af5623206ed767be9c66da7d6f7eba511871d9da61456026b7f310e15e3359ac41ec926020dd0e078b30ad16780690abae311be0130c2a9a030d0d65c8f12aec3264ed853b208934595bab6108f9b2e6fa75d4e1d285eb79791c5e7610358acd626a4b17022120b93879c9b8476d6b3952933c83a07ac6aeeb01f6bc971b6740da7614a47da958203a6ac56a4149e8c9bd8119e3ab6fa7780bda6fc14d6119c416a11a1bc1c0b60d2048917eaa9b4c094d69ec54970475d3df466a984ee9aed707970c69bc958f6e61209eed88e4f9bb67d455f9aebdb6ab4ef8b566b03f230804c7f58214043bd4e471202cd2e15a6e521b4ff874c7261fcba80b7782526f236bf73435ce20eb136d4c33203ea72374fe684e6a8eb5d4980633218da196cab396fcdddf6831953298f3e45520798e3416956611fa66571e10e50b8b2c0abf537f16afc725ced4ece6b279142420806ab1a3c089454e16575ceece1e3aefee2a6184255e18a2343fb7feb86b7e6d204e8e59d04c3f4469e9d58483fc8539db868cf2334f4257121ad6f80db6c9702d204c66cea9b58243efbe2e62d1da3a03a48cfbce68ef212b3c77acb1e12c5ab962205b5714543c02aa922a6620e12e901943fc5b03bb9ae1586c002d639570326707203aa41a68aac5b5e125616c1c4efb4a00e08ca4f8e65e66a1470d7c47c72a140f2039cf8d1399cea0bbb22c31ff1ed14be62acb70e75f13aa0757c29d76b943a53e20eef109b0196c0f0062e70a30dec6092fc4b4ed9c9474ab21fe9e15888242173f20470b80510859a91cfe7a601886d45d0d639df7a3cc9bebca31aaf0576289d85e2052bd935980c463ccee5345e4912cfdbbcc7c82d3cdb4077b105a57879ffbb70d030000000000000003bc4834ed020000804c0f3ddf65a15f86e4bad5214a97cab34339fcc1f12ed6a7d3f2e41af052584ea01b3b0d4047c0dc74ae4c433a1c374d66851fd3dd30f7cc10870b45c5a8c0c8f3ef8e52cee9d1b303cc3b03dc8f71f592ba5e641e7620fe7d52fd6dd64a13342bd03f1b3b0ef4a844e475666c848b98e53d6e7f9f92f022770da543d1f370d80b052443197255c12e5bbacab7ea57bc7d86c9378b2f21973e7afadf1f603d0f68aae34e4e6104f26d815bcffc144a76f1deb9d92ef1ec846c26d52e22624a1bef50023f09cc1c7181e09e0027b929000000004cd2304462c7a3cfe98580530fb73e66cf007d2a6efdb1a78e95bdaefe346970901526c37a6128231cda8f074b53d979d93ba71adfd24d2faea20d5cf8756008026b2f2322ea3ed01da2bbfe29598480f167469ae63986df30cb8458ab131926ee2020de43f9cb72ec5b01c93aff1981a6cb7765b3e0c60ecdd4f0ddc1f1dda252ff0e20ad15f9b7057e4431f40b17d3cc76194d8339b1ddd9d80b20352002634663642e2089fd643bbfeef5b486e4e29e1c99d72c29944791c32fc225396b59318681b633208ef64e2cbb03d5af593244b253abc3e94db3b9150596e17303940d4eb2d5781a20a5461d4e8bd352703204beb6277e50a2c27e7779f7ab98fd45ceb0bba5c1b901203b52fb113249110b4566887d79a9693c3be69572a5b90b690702066e97ef155c204b07ba48cb4a793c01dfeb6392195b6493f3ceed52b5cea7df7279220e967e47204147f5d495d644e9c246093bdba51a94d44de39bb435f3410b52969570babe6d20b522e12ee1a1aa449be27411bbf4f8bdf90a8a816b7144f28991fa307644541b20d88bbcd3447046ef164ce336bdb9d6d29f4367d2f8aa7d39644e87c9c1ecca05202d7708b49a8ab745c2f51f638649c6a455842a6f4e040aae4d9885546337245920897423682b6d8f56fce75bf9c4a7f70f35dfa7386e554e7c561a62a835c3a3662049c2d8eff3e9c0a5a2017de57ab4e2c12eea2cf06228127f26580f4fa9af5623206ed767be9c66da7d6f7eba511871d9da61456026b7f310e15e3359ac41ec926020dd0e078b30ad16780690abae311be0130c2a9a030d0d65c8f12aec3264ed853b208934595bab6108f9b2e6fa75d4e1d285eb79791c5e7610358acd626a4b17022120b93879c9b8476d6b3952933c83a07ac6aeeb01f6bc971b6740da7614a47da958203a6ac56a4149e8c9bd8119e3ab6fa7780bda6fc14d6119c416a11a1bc1c0b60d2048917eaa9b4c094d69ec54970475d3df466a984ee9aed707970c69bc958f6e61209eed88e4f9bb67d455f9aebdb6ab4ef8b566b03f230804c7f58214043bd4e471202cd2e15a6e521b4ff874c7261fcba80b7782526f236bf73435ce20eb136d4c33203ea72374fe684e6a8eb5d4980633218da196cab396fcdddf6831953298f3e45520798e3416956611fa66571e10e50b8b2c0abf537f16afc725ced4ece6b279142420806ab1a3c089454e16575ceece1e3aefee2a6184255e18a2343fb7feb86b7e6d204e8e59d04c3f4469e9d58483fc8539db868cf2334f4257121ad6f80db6c9702d204c66cea9b58243efbe2e62d1da3a03a48cfbce68ef212b3c77acb1e12c5ab962205b5714543c02aa922a6620e12e901943fc5b03bb9ae1586c002d639570326707203aa41a68aac5b5e125616c1c4efb4a00e08ca4f8e65e66a1470d7c47c72a140f2039cf8d1399cea0bbb22c31ff1ed14be62acb70e75f13aa0757c29d76b943a53e20adac55dbaaf042eb4336ed7bf212c129caea9bad0e3f220824a63fc298a5f26420015bd20c84e477f2c7124f50ae7ff2574d8bed0d94d3ee1ea381abcaa7154b3820638b1629f393a1d4304aed11d3cf9512b4580ac91f789d097bec294acabfe15b050000000000000003bc4834ed020000804c0f3ddf65a15f86e4bad5214a97cab34339fcc1f12ed6a7d3f2e41af052584ea01b3b0d4047c0dc74ae4c433a1c374d66851fd3dd30f7cc10870b45c5a8c0c8f3ef8e52cee9d1b303cc3b03dc8f71f592ba5e641e7620fe7d52fd6dd64a13342bd03f1b3b0ef4a844e475666c848b98e53d6e7f9f92f022770da543d1f370d80b052443197255c12e5bbacab7ea57bc7d86c9378b2f21973e7afadf1f603d0f68aae34e4e6104f26d815bc445c134937afce1f5f82a5cbccbce2de33705574db76184ce8aaa3e3eff79af0046c323000000004cd2304462c7a3cfe98580530fb73e66cf007d2a6efdb1a78e95bdaefe346970901526c37a6128231cda8f074b53d979d93ba71adfd24d2faea20d5cf8756008029f78730f173168a8137669f37342c89072fdbd55d7b2398f72ac70a6567506c92020de43f9cb72ec5b01c93aff1981a6cb7765b3e0c60ecdd4f0ddc1f1dda252ff0e20ad15f9b7057e4431f40b17d3cc76194d8339b1ddd9d80b20352002634663642e2089fd643bbfeef5b486e4e29e1c99d72c29944791c32fc225396b59318681b633208ef64e2cbb03d5af593244b253abc3e94db3b9150596e17303940d4eb2d5781a20a5461d4e8bd352703204beb6277e50a2c27e7779f7ab98fd45ceb0bba5c1b901203b52fb113249110b4566887d79a9693c3be69572a5b90b690702066e97ef155c204b07ba48cb4a793c01dfeb6392195b6493f3ceed52b5cea7df7279220e967e47204147f5d495d644e9c246093bdba51a94d44de39bb435f3410b52969570babe6d20b522e12ee1a1aa449be27411bbf4f8bdf90a8a816b7144f28991fa307644541b20d88bbcd3447046ef164ce336bdb9d6d29f4367d2f8aa7d39644e87c9c1ecca05202d7708b49a8ab745c2f51f638649c6a455842a6f4e040aae4d9885546337245920897423682b6d8f56fce75bf9c4a7f70f35dfa7386e554e7c561a62a835c3a3662049c2d8eff3e9c0a5a2017de57ab4e2c12eea2cf06228127f26580f4fa9af5623206ed767be9c66da7d6f7eba511871d9da61456026b7f310e15e3359ac41ec926020dd0e078b30ad16780690abae311be0130c2a9a030d0d65c8f12aec3264ed853b208934595bab6108f9b2e6fa75d4e1d285eb79791c5e7610358acd626a4b17022120b93879c9b8476d6b3952933c83a07ac6aeeb01f6bc971b6740da7614a47da958203a6ac56a4149e8c9bd8119e3ab6fa7780bda6fc14d6119c416a11a1bc1c0b60d2048917eaa9b4c094d69ec54970475d3df466a984ee9aed707970c69bc958f6e61209eed88e4f9bb67d455f9aebdb6ab4ef8b566b03f230804c7f58214043bd4e471202cd2e15a6e521b4ff874c7261fcba80b7782526f236bf73435ce20eb136d4c33203ea72374fe684e6a8eb5d4980633218da196cab396fcdddf6831953298f3e45520798e3416956611fa66571e10e50b8b2c0abf537f16afc725ced4ece6b279142420806ab1a3c089454e16575ceece1e3aefee2a6184255e18a2343fb7feb86b7e6d204e8e59d04c3f4469e9d58483fc8539db868cf2334f4257121ad6f80db6c9702d204c66cea9b58243efbe2e62d1da3a03a48cfbce68ef212b3c77acb1e12c5ab962205b5714543c02aa922a6620e12e901943fc5b03bb9ae1586c002d639570326707203aa41a68aac5b5e125616c1c4efb4a00e08ca4f8e65e66a1470d7c47c72a140f2039cf8d1399cea0bbb22c31ff1ed14be62acb70e75f13aa0757c29d76b943a53e20adac55dbaaf042eb4336ed7bf212c129caea9bad0e3f220824a63fc298a5f264201e07954176ff601fbb9899a9a62f6d305b90cbfb17cbd0519eec3e29f0ae095a200a0599a264ccf8a4a3f6968121e98312f8b2131bbdaee77a29e55cb4b8d4906c07000000000000000300000002223aca207e54efd1ceea59fc8ecf353939c0a8f50d84398fc7dba2b24a7b15bef803000000000000000000000000000077ba2d68bff406134b52a1ce23d1d76e299cab1343dd6f29cc9180e5b9a97ecc18fcffffffffffffffffffffffffffffcae1c81ec7eb83670a674af27bbb83225bc84546d5d65528d2384df7ddf715ede6000000000000002020de43f9cb72ec5b01c93aff1981a6cb7765b3e0c60ecdd4f0ddc1f1dda252ff0e20ad15f9b7057e4431f40b17d3cc76194d8339b1ddd9d80b20352002634663642e2089fd643bbfeef5b486e4e29e1c99d72c29944791c32fc225396b59318681b633208ef64e2cbb03d5af593244b253abc3e94db3b9150596e17303940d4eb2d5781a20a5461d4e8bd352703204beb6277e50a2c27e7779f7ab98fd45ceb0bba5c1b901203b52fb113249110b4566887d79a9693c3be69572a5b90b690702066e97ef155c204b07ba48cb4a793c01dfeb6392195b6493f3ceed52b5cea7df7279220e967e47204147f5d495d644e9c246093bdba51a94d44de39bb435f3410b52969570babe6d20b522e12ee1a1aa449be27411bbf4f8bdf90a8a816b7144f28991fa307644541b20d88bbcd3447046ef164ce336bdb9d6d29f4367d2f8aa7d39644e87c9c1ecca05202d7708b49a8ab745c2f51f638649c6a455842a6f4e040aae4d9885546337245920897423682b6d8f56fce75bf9c4a7f70f35dfa7386e554e7c561a62a835c3a3662049c2d8eff3e9c0a5a2017de57ab4e2c12eea2cf06228127f26580f4fa9af5623206ed767be9c66da7d6f7eba511871d9da61456026b7f310e15e3359ac41ec926020dd0e078b30ad16780690abae311be0130c2a9a030d0d65c8f12aec3264ed853b208934595bab6108f9b2e6fa75d4e1d285eb79791c5e7610358acd626a4b17022120b93879c9b8476d6b3952933c83a07ac6aeeb01f6bc971b6740da7614a47da958203a6ac56a4149e8c9bd8119e3ab6fa7780bda6fc14d6119c416a11a1bc1c0b60d2048917eaa9b4c094d69ec54970475d3df466a984ee9aed707970c69bc958f6e61209eed88e4f9bb67d455f9aebdb6ab4ef8b566b03f230804c7f58214043bd4e471202cd2e15a6e521b4ff874c7261fcba80b7782526f236bf73435ce20eb136d4c33203ea72374fe684e6a8eb5d4980633218da196cab396fcdddf6831953298f3e45520798e3416956611fa66571e10e50b8b2c0abf537f16afc725ced4ece6b279142420806ab1a3c089454e16575ceece1e3aefee2a6184255e18a2343fb7feb86b7e6d203e971597ab1bca5847d088e1df809509b46d855b7375e48c3c4f94cb033f5216201be5677eb1c6da8d6369ad889e9abc6ffd8e514b67944bbccc5da8b191cb6d7220513758197818eb55d70ce9df92680cffdec26f44e192b7bfd292491b9f0e614720af25f1a654c0b80f762b0c51321a4255c98021d87236a7c5625b390a5fb63e2120b20f69ede074cd4c6ebda44dbdfd1de4ce6e7b35d8a7fa91ec25ab7b53cd2d46208bd400072189b13ff4e8fd176df6985ff2b8340f3ec944f0a72ea3f207cf8010206a6b058e767c1fbaf2bf5038eef201c2781b90a4a3e0cd02a886cda9c781e70820bd457b3cc2c640ac4dd7dec85d1c9961b86702618c48dfb74295411998d0fe583b000000000000000377ba2d68bff406134b52a1ce23d1d76e299cab1343dd6f29cc9180e5b9a97ecc08000000000000000000000000000000c445c134937afce1f5f82a5cbccbce2de33705574db76184ce8aaa3e3eff79af6079feffffffffffffffffffffffffffd76005782fa1af6c4810d98fff2ca0259183b23ea5b23a81a0a83bdd8648626ea086010000000000000000000000000093c9b0f8d619238fa6e08c4ba9e2b220db3e108725d92ae0be90d5454d1fe75670170000000000002020de43f9cb72ec5b01c93aff1981a6cb7765b3e0c60ecdd4f0ddc1f1dda252ff0e20ad15f9b7057e4431f40b17d3cc76194d8339b1ddd9d80b20352002634663642e2089fd643bbfeef5b486e4e29e1c99d72c29944791c32fc225396b59318681b633208ef64e2cbb03d5af593244b253abc3e94db3b9150596e17303940d4eb2d5781a20a5461d4e8bd352703204beb6277e50a2c27e7779f7ab98fd45ceb0bba5c1b901203b52fb113249110b4566887d79a9693c3be69572a5b90b690702066e97ef155c204b07ba48cb4a793c01dfeb6392195b6493f3ceed52b5cea7df7279220e967e47204147f5d495d644e9c246093bdba51a94d44de39bb435f3410b52969570babe6d20b522e12ee1a1aa449be27411bbf4f8bdf90a8a816b7144f28991fa307644541b20d88bbcd3447046ef164ce336bdb9d6d29f4367d2f8aa7d39644e87c9c1ecca05202d7708b49a8ab745c2f51f638649c6a455842a6f4e040aae4d9885546337245920897423682b6d8f56fce75bf9c4a7f70f35dfa7386e554e7c561a62a835c3a3662049c2d8eff3e9c0a5a2017de57ab4e2c12eea2cf06228127f26580f4fa9af5623206ed767be9c66da7d6f7eba511871d9da61456026b7f310e15e3359ac41ec926020dd0e078b30ad16780690abae311be0130c2a9a030d0d65c8f12aec3264ed853b208934595bab6108f9b2e6fa75d4e1d285eb79791c5e7610358acd626a4b17022120b93879c9b8476d6b3952933c83a07ac6aeeb01f6bc971b6740da7614a47da958203a6ac56a4149e8c9bd8119e3ab6fa7780bda6fc14d6119c416a11a1bc1c0b60d2048917eaa9b4c094d69ec54970475d3df466a984ee9aed707970c69bc958f6e61209eed88e4f9bb67d455f9aebdb6ab4ef8b566b03f230804c7f58214043bd4e471202cd2e15a6e521b4ff874c7261fcba80b7782526f236bf73435ce20eb136d4c33203ea72374fe684e6a8eb5d4980633218da196cab396fcdddf6831953298f3e45520798e3416956611fa66571e10e50b8b2c0abf537f16afc725ced4ece6b279142420806ab1a3c089454e16575ceece1e3aefee2a6184255e18a2343fb7feb86b7e6d203e971597ab1bca5847d088e1df809509b46d855b7375e48c3c4f94cb033f5216208dcce50d00f33100383f9e310c334158bdb7721fa5580dd7060c1eb51c7c7f6920224b4dc465164ced7d9cc6ad4e38639f39d9d3eb259af7acfcc6889542b9db2820725d01640e2526401045ab378694d9c9c960b3b5afa416616f4ff8646d35256c20c5c23be9c51ff57fac755702af301308ecb351b07b6f7d07f3c279176bb699732040386d07148003de6063e628c980113597b1be3429d6fe48535bb565c7f75c5d20382db2f5195b26b2636a955747d8464d0b315a7827ef3fd2d9a8165ade89df362060f0ff263e1f267b26ae4d8b696439d2513fc69ccac1117e4e73ebb28253544262000000000000000377ba2d68bff406134b52a1ce23d1d76e299cab1343dd6f29cc9180e5b9a97ecc0d000000000000000000000000000000cffc144a76f1deb9d92ef1ec846c26d52e22624a1bef50023f09cc1c7181e09e6079feffffffffffffffffffffffffffd76005782fa1af6c4810d98fff2ca0259183b23ea5b23a81a0a83bdd8648626ea086010000000000000000000000000045ce4761d864dbec59a05d91291ab0a9a8f137e65c4376d122b1efcf85531dc8b0360000000000002020de43f9cb72ec5b01c93aff1981a6cb7765b3e0c60ecdd4f0ddc1f1dda252ff0e20ad15f9b7057e4431f40b17d3cc76194d8339b1ddd9d80b20352002634663642e2089fd643bbfeef5b486e4e29e1c99d72c29944791c32fc225396b59318681b633208ef64e2cbb03d5af593244b253abc3e94db3b9150596e17303940d4eb2d5781a20a5461d4e8bd352703204beb6277e50a2c27e7779f7ab98fd45ceb0bba5c1b901203b52fb113249110b4566887d79a9693c3be69572a5b90b690702066e97ef155c204b07ba48cb4a793c01dfeb6392195b6493f3ceed52b5cea7df7279220e967e47204147f5d495d644e9c246093bdba51a94d44de39bb435f3410b52969570babe6d20b522e12ee1a1aa449be27411bbf4f8bdf90a8a816b7144f28991fa307644541b20d88bbcd3447046ef164ce336bdb9d6d29f4367d2f8aa7d39644e87c9c1ecca05202d7708b49a8ab745c2f51f638649c6a455842a6f4e040aae4d9885546337245920897423682b6d8f56fce75bf9c4a7f70f35dfa7386e554e7c561a62a835c3a3662049c2d8eff3e9c0a5a2017de57ab4e2c12eea2cf06228127f26580f4fa9af5623206ed767be9c66da7d6f7eba511871d9da61456026b7f310e15e3359ac41ec926020dd0e078b30ad16780690abae311be0130c2a9a030d0d65c8f12aec3264ed853b208934595bab6108f9b2e6fa75d4e1d285eb79791c5e7610358acd626a4b17022120b93879c9b8476d6b3952933c83a07ac6aeeb01f6bc971b6740da7614a47da958203a6ac56a4149e8c9bd8119e3ab6fa7780bda6fc14d6119c416a11a1bc1c0b60d2048917eaa9b4c094d69ec54970475d3df466a984ee9aed707970c69bc958f6e61209eed88e4f9bb67d455f9aebdb6ab4ef8b566b03f230804c7f58214043bd4e471202cd2e15a6e521b4ff874c7261fcba80b7782526f236bf73435ce20eb136d4c33203ea72374fe684e6a8eb5d4980633218da196cab396fcdddf6831953298f3e45520798e3416956611fa66571e10e50b8b2c0abf537f16afc725ced4ece6b279142420806ab1a3c089454e16575ceece1e3aefee2a6184255e18a2343fb7feb86b7e6d203e971597ab1bca5847d088e1df809509b46d855b7375e48c3c4f94cb033f5216208dcce50d00f33100383f9e310c334158bdb7721fa5580dd7060c1eb51c7c7f6920224b4dc465164ced7d9cc6ad4e38639f39d9d3eb259af7acfcc6889542b9db2820725d01640e2526401045ab378694d9c9c960b3b5afa416616f4ff8646d35256c208a8b7015bab696bea93dc5b94ec2a680bcf08b38c4e7d4c1c47babed858e1e732016c62413b1cadfd235534d147694a3cf205ea8540430d9e17b7598e34ac949522022ca988bc76af4e2c81c6eb23fb545ae4692f481d04b4a124b58b17ab371dc412095ed9e12ba9285ea2ec94ce14ba4e7b8f5d150ede0874bd170786247e9c4b4146f0000000000000001000000012bd03f1b3b0ef4a844e475666c848b98e53d6e7f9f92f022770da543d1f370d8ee7f4b5caa9034471504c8c4875270d7d638df9337e46ba0ac80b1fd93ebb88d36580a0b8dbab200289e96223aca207e54efd1ceea59fc8ecf353939c0a8f50d84398fc7dba2b24a7b15bed090030000000000a1fb6c578a969fec10b1c4f164669384151f06f1cc1c8142370c01df29dd54e6c4875270d7d638df9337e46ba0ac80b1fd93ebb88d36580a0b8dbab200289e96f600000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000022cd879c6ca49e1cf008452b66ba759d3bfdcf1ddbe62d5522409f82e21e38d8487276bf67d478f410e011000000074785f7472616e736665722e7761736d00d19c0da962918c07ac00000001000000020c000e797496138ebe935066f9ab58c6950cda45da03009435770000000000000000000000000000000000000000000000000000000008010000000019b32743a64a892c0a0ba136a01ef5f66ab1ca1a000e797496138ebe935066f9ab58c6950cda45da03009435770000000000000000000000000000000000000000000000000000000008011851abe9b403ecf912a68fe29942e1dc6ab95e7faecf3fbc466f679fd73ae222").expect("unable to decode bytes");
    let transport = WalletTransport::from_arg(args::DeviceTransport::Hid);
    let app = NamadaApp::new(transport);
    let path = BIP44Path {
        path: "m/32'/877'/2'".to_string(),
    };
    app.clean_randomness_buffers().await.expect("unable to clean randomness buffer");
    // Get randomness to aid in construction of various descriptors
    let mut bparams = StoredBuildParams::default();
    for _ in 0..10 {
        let spend_randomness = app
            .get_spend_randomness()
            .await
            .expect("unable to get spend randomness");
        bparams.spend_params.push(SpendBuildParams {
            rcv: jubjub::Fr::from_bytes(&spend_randomness.rcv).unwrap(),
            alpha: jubjub::Fr::from_bytes(&spend_randomness.alpha).unwrap(),
        });
    }
    for _ in 0..10 {
        let convert_randomness = app
            .get_convert_randomness()
            .await
            .expect("unable to get spend randomness");
        bparams.convert_params.push(ConvertBuildParams {
            rcv: jubjub::Fr::from_bytes(&convert_randomness.rcv).unwrap(),
        });
    }
    for _ in 0..10 {
        let output_randomness = app
            .get_output_randomness()
            .await
            .expect("unable to get spend randomness");
        bparams.output_params.push(OutputBuildParams {
            rcv: jubjub::Fr::from_bytes(&output_randomness.rcv).unwrap(),
            rseed: output_randomness.rcm,
            ..OutputBuildParams::default()
        });
    }
    let mut tx = Tx::try_from_slice(&tx_bytes).expect("unable to deserialize Tx");
    let mut masp_tx = None;
    for sec in &mut tx.sections {
        if let Section::MaspBuilder(builder) = sec {
            let (sender, _receiver) = std::sync::mpsc::channel();
            let mut rng = StdRng::from_rng(OsRng).expect("unable to create new PRNG");
            let prover_rng = StdRng::from_rng(OsRng).expect("unable to create new PRNG");
            let mut sk_map = HashMap::new();
            let vk = ExtendedViewingKey::from_str("zvknam1qw7ysd8dqqqqpq87tuc795aa2ggh06tfqwa04m4pluu2l07g00yjllvt475l37fecup3h8fasw8mqdp6cfj2adut4yy7tfe3e4arkntqrt64hl0ypc4kmuxpfp0cyqdtze6uqrgjq8933u8w4ry7jtfxrz0ujuu9gnpwg9pajpusmvwcyvk8gtarc3pha9vzw623jk9mywfvnh4axf0nqevzm2n26z39jxmvdt29n73drqgqtmh0nqhr0zuq06csjf66az0j3ruxd9cvx4vjd").expect("unable to construct viewing key");
            let sk = ExtendedSpendingKey::from_str("zsknam1qw7ysd8dqqqqpq87tuc795aa2ggh06tfqwa04m4pluu2l07g00yjllvt475l37fecurmeysgmntwvg4x4t9tswwz8snyqnxnv23n5ma4l85cwxm9v5hqngdg72t4utfpah4vg76h7u9darlldm092pyat0j2rj2ae0ky0mgvjpusmvwcyvk8gtarc3pha9vzw623jk9mywfvnh4axf0nqevzm2n26z39jxmvdt29n73drqgqtmh0nqhr0zuq06csjf66az0j3ruxd9cylq40c").expect("unable to construct spending key");
            sk_map.insert(vk, sk);
            let vk = ExtendedViewingKey::from_str("zvknam1qw7ysd8dqyqqpqp3rpe8e66t6y7elv4p5xgqh7904ck0ch87nsu8m3ftxnzzydg6l8q9yuzmczdgp9zjh4w8dtpmr880mn0r6wzefz35zdcucwqc8v2gz5cne222tszq20z9etczeeqs498zpjprfvkjl8uzqxcqp5a7665x6fuxdh8p8mn2haeryp8yjk4np6ka4xsdtmfw2hjwq3s7mk07pc6gjllc0u4yjnwu8fklf40rvcvgwqn6t87x97nd8ajqrgdffayv48q54ghg7").expect("unable to construct viewing key");
            let sk = ExtendedSpendingKey::from_str("zsknam1qw7ysd8dqyqqpqp3rpe8e66t6y7elv4p5xgqh7904ck0ch87nsu8m3ftxnzzydg6lxlfc7z4as4774mt4k74natfudlem5qehcuhhdmrmh8l8wwyd95qqyedjea4sc5req2qqr7tp77u2k9xly7t782cmddf7847fmevg0gy6fuxdh8p8mn2haeryp8yjk4np6ka4xsdtmfw2hjwq3s7mk07pc6gjllc0u4yjnwu8fklf40rvcvgwqn6t87x97nd8ajqrgdffayv48q3nsgd3").expect("unable to construct spending key");
            sk_map.insert(vk, sk);
            let vk = ExtendedViewingKey::from_str("zvknam1qw7ysd8dqgqqpqzvpu7a7edpt7rwfwk4y99f0j4ngvules039mt205ljusd0q5jcf6spkwcdgpruphr54exyxwsuxaxkdpgl60wnpa7vzzrsk3w94rqv3ul03efva6w3kvpucwcrmj8hravjhf0xg8nkyrl865hadhty5ye590gr7xempm62s38yw4nxepytnrjn6mnln7f0qgnhpkj5850nwrvqkpfygvvhy4wp9edm4j4haftmclvxeymcktepjul847klrasr6rctw0mw8").expect("unable to construct viewing key");
            let sk = ExtendedSpendingKey::from_str("zsknam1qw7ysd8dqgqqpqzvpu7a7edpt7rwfwk4y99f0j4ngvules039mt205ljusd0q5jcfmlcg2tn3y5pnq59tghcnz6dqk5xhxlqvq6ym5x260zlc0wf8zxqt88r0t9v2239fvqgwm74zht4njkkzjddp8w9j8s9h277cg24v6qt90gr7xempm62s38yw4nxepytnrjn6mnln7f0qgnhpkj5850nwrvqkpfygvvhy4wp9edm4j4haftmclvxeymcktepjul847klrasr6rcaetg30").expect("unable to construct spending key");
            sk_map.insert(vk, sk);
            let (transaction, metadata) = builder.builder.clone().map_builder(WalletMap {
                params: NETWORK,
                notifier: sender,
                keys: |vk: &ExtendedFullViewingKey| {
                    let vk = ExtendedViewingKey::from(vk.clone());
                    let sk = sk_map.get(&vk).expect("unable to reverse look-up viewing key").clone();
                    let sk = masp_primitives::zip32::ExtendedSpendingKey::from(sk);
                    PseudoExtendedKey::from(sk)
                },
                phantom: PhantomData,
            }).build(
                &MockTxProver(Mutex::new(prover_rng)),
                &FeeRule::non_standard(U64Sum::zero()),
                &mut rng,
                &mut bparams,
            ).expect("unable to rebuild Transaction");
            builder.metadata = metadata;
            builder.target = transaction.txid().into();
            masp_tx = Some(transaction);
        }
    }
    let masp_tx = masp_tx.expect("Transaction was not rebuilt");
    let mut data_sechash = None;
    for sec in &mut tx.sections {
        if let Section::MaspTx(transaction) = sec {
            println!("hey");
            *transaction = masp_tx.clone();
        } else if let Section::Data(data) = sec {
            if let Ok(mut transfer) = Transfer::try_from_slice(&data.data) {
                println!("bye");
                transfer.shielded_section_hash = Some(masp_tx.txid().into());
                data.data = transfer.serialize_to_vec();
                data_sechash = Some(Section::Data(data.clone()).get_hash());
            }
        }
    }
    tx.set_data_sechash(data_sechash.expect("unable to get data section hash"));
    app.sign_masp_spends(&path, &tx.serialize_to_vec())
        .await
        .expect("unable to sign MASP Transaction");
    for _ in 0..3 {
        app.sign_masp_spends(&path, &tx.serialize_to_vec())
            .await
            .expect("unable to obtain spend signature");
    }
}

pub async fn submit_shielded_transfer(
    namada: &impl Namada,
    mut args: args::TxShieldedTransfer,
) -> Result<(), error::Error> {
    display_line!(
        namada.io(),
        "{}: {}\n",
        "WARNING".bold().underline().yellow(),
        "Some information might be leaked if your shielded wallet is not up \
         to date, make sure to run `namadac shielded-sync` before running \
         this command.",
    );

    let sources = args
        .data
        .iter_mut()
        .map(|x| &mut x.source)
        .chain(args.gas_spending_key.iter_mut());
    let shielded_hw_keys =
        augment_masp_hardware_keys(namada, &args.tx, sources).await?;
    let mut bparams = generate_masp_build_params(
        MAX_HW_SPEND,
        MAX_HW_CONVERT,
        MAX_HW_OUTPUT,
        &args.tx,
    )
    .await?;
    let (mut tx, signing_data) =
        args.clone().build(namada, &mut bparams).await?;
    println!("Tx Bytes: {}", data_encoding::HEXLOWER.encode(&tx.serialize_to_vec()));
    println!("Test Vector: {:?}", namada_sdk::signing::to_ledger_vector(&*namada.wallet().await, &tx).await);
    println!("Tx Debug: {:?}", tx);
    println!();
    masp_sign(&mut tx, &args.tx, &signing_data, shielded_hw_keys).await?;

    let masp_section = tx
        .sections
        .iter()
        .find_map(|section| section.masp_tx())
        .ok_or_else(|| {
            error::Error::Other(
                "Missing MASP section in shielded transaction".to_string(),
            )
        })?;
    if args.tx.dump_tx || args.tx.dump_wrapper_tx {
        tx::dump_tx(namada.io(), &args.tx, tx)?;
        pre_cache_masp_data(namada, &masp_section).await;
    } else {
        sign(namada, &mut tx, &args.tx, signing_data).await?;
        let res = namada.submit(tx, &args.tx).await?;
        pre_cache_masp_data_on_tx_result(namada, &res, &masp_section).await;
    }
    Ok(())
}

pub async fn submit_shielding_transfer(
    namada: &impl Namada,
    args: args::TxShieldingTransfer,
) -> Result<(), error::Error> {
    // Repeat once if the tx fails on a crossover of an epoch
    for _ in 0..2 {
        let mut bparams = generate_masp_build_params(
            MAX_HW_SPEND,
            MAX_HW_CONVERT,
            MAX_HW_OUTPUT,
            &args.tx,
        )
        .await?;
        let (tx, signing_data, tx_epoch) =
            args.clone().build(namada, &mut bparams).await?;

        if args.tx.dump_tx || args.tx.dump_wrapper_tx {
            tx::dump_tx(namada.io(), &args.tx, tx)?;
            break;
        }

        let cmt_hash = tx.commitments().last().unwrap().get_hash();
        let wrapper_hash = tx.wrapper_hash();

        let reveal_pks: Vec<_> =
            args.data.iter().map(|datum| &datum.source).collect();
        let result = batch_opt_reveal_pk_and_submit(
            namada,
            &args.tx,
            &reveal_pks,
            (tx, signing_data),
        )
        .await?;

        // Check the need for a resubmission
        if let ProcessTxResponse::Applied(resp) = result {
            if let Some(InnerTxResult::VpsRejected(result)) =
                resp.batch_result().get(&compute_inner_tx_hash(
                    wrapper_hash.as_ref(),
                    either::Left(&cmt_hash),
                ))
            {
                let rejected_vps = &result.vps_result.rejected_vps;
                let vps_errors = &result.vps_result.errors;
                // If the transaction is rejected by the MASP VP only and
                // because of an asset's epoch issue
                if rejected_vps.len() == 1
                    && (vps_errors.contains(&(
                        MASP,
                        "Native VP error: epoch is missing from asset type"
                            .to_string(),
                    )) || vps_errors.contains(&(
                        MASP,
                        "Native VP error: Unable to decode asset type"
                            .to_string(),
                    )))
                {
                    let submission_masp_epoch =
                        rpc::query_and_print_masp_epoch(namada).await;
                    // And its submission epoch doesn't match construction
                    // epoch
                    if tx_epoch != submission_masp_epoch {
                        // Then we probably straddled an epoch boundary.
                        // Let's retry...
                        edisplay_line!(
                            namada.io(),
                            "Shielding transaction rejected and this may be \
                             due to the epoch changing. Attempting to \
                             resubmit transaction.",
                        );
                        continue;
                    }
                }
            }
        }

        // Otherwise either the transaction was successful or it will not
        // benefit from resubmission
        break;
    }
    Ok(())
}

pub async fn submit_unshielding_transfer(
    namada: &impl Namada,
    mut args: args::TxUnshieldingTransfer,
) -> Result<(), error::Error> {
    display_line!(
        namada.io(),
        "{}: {}\n",
        "WARNING".bold().underline().yellow(),
        "Some information might be leaked if your shielded wallet is not up \
         to date, make sure to run `namadac shielded-sync` before running \
         this command.",
    );

    let sources = std::iter::once(&mut args.source)
        .chain(args.gas_spending_key.iter_mut());
    let shielded_hw_keys =
        augment_masp_hardware_keys(namada, &args.tx, sources).await?;
    let mut bparams = generate_masp_build_params(
        MAX_HW_SPEND,
        MAX_HW_CONVERT,
        MAX_HW_OUTPUT,
        &args.tx,
    )
    .await?;
    let (mut tx, signing_data) =
        args.clone().build(namada, &mut bparams).await?;
    println!("Tx Bytes: {}", data_encoding::HEXLOWER.encode(&tx.serialize_to_vec()));
    println!("Test Vector: {:?}", namada_sdk::signing::to_ledger_vector(&*namada.wallet().await, &tx).await);
    println!("Tx Debug: {:?}", tx);
    println!();
    masp_sign(&mut tx, &args.tx, &signing_data, shielded_hw_keys).await?;

    let masp_section = tx
        .sections
        .iter()
        .find_map(|section| section.masp_tx())
        .ok_or_else(|| {
            error::Error::Other(
                "Missing MASP section in shielded transaction".to_string(),
            )
        })?;
    if args.tx.dump_tx || args.tx.dump_wrapper_tx {
        tx::dump_tx(namada.io(), &args.tx, tx)?;
        pre_cache_masp_data(namada, &masp_section).await;
    } else {
        sign(namada, &mut tx, &args.tx, signing_data).await?;
        let res = namada.submit(tx, &args.tx).await?;
        pre_cache_masp_data_on_tx_result(namada, &res, &masp_section).await;
    }
    Ok(())
}

pub async fn submit_ibc_transfer<N: Namada>(
    namada: &N,
    mut args: args::TxIbcTransfer,
) -> Result<(), error::Error>
where
    <N::Client as namada_sdk::io::Client>::Error: std::fmt::Display,
{
    let sources = args
        .source
        .spending_key_mut()
        .into_iter()
        .chain(args.gas_spending_key.iter_mut());
    let shielded_hw_keys =
        augment_masp_hardware_keys(namada, &args.tx, sources).await?;
    // Try to generate MASP build parameters. This might fail when using a
    // hardware wallet if it does not support MASP operations.
    let bparams_result = generate_masp_build_params(
        MAX_HW_SPEND,
        MAX_HW_CONVERT,
        MAX_HW_OUTPUT,
        &args.tx,
    )
    .await;
    // If MASP build parameter generation failed for any reason, then try to
    // build the transaction with no parameters. Remember the error though.
    let (mut bparams, bparams_err) = bparams_result.map_or_else(
        |e| (Box::new(StoredBuildParams::default()) as _, Some(e)),
        |bparams| (bparams, None),
    );
    // If transaction building fails for any reason, then abort the process
    // blaming MASP build parameter generation if that had also failed.
    let (mut tx, signing_data, _) = args
        .build(namada, &mut bparams)
        .await
        .map_err(|e| bparams_err.unwrap_or(e))?;
    // Any effects of a MASP build parameter generation failure would have
    // manifested during transaction building. So we discount that as a root
    // cause from now on.
    println!("Tx Bytes: {}", data_encoding::HEXLOWER.encode(&tx.serialize_to_vec()));
    println!("Test Vector: {:?}", namada_sdk::signing::to_ledger_vector(&*namada.wallet().await, &tx).await);
    println!("Tx Debug: {:?}", tx);
    println!();
    masp_sign(&mut tx, &args.tx, &signing_data, shielded_hw_keys).await?;

    let opt_masp_section =
        tx.sections.iter().find_map(|section| section.masp_tx());
    if args.tx.dump_tx || args.tx.dump_wrapper_tx {
        tx::dump_tx(namada.io(), &args.tx, tx)?;
        if let Some(masp_section) = opt_masp_section {
            pre_cache_masp_data(namada, &masp_section).await;
        }
    } else {
        let res = batch_opt_reveal_pk_and_submit(
            namada,
            &args.tx,
            &[&args.source.effective_address()],
            (tx, signing_data),
        )
        .await?;

        if let Some(masp_section) = opt_masp_section {
            pre_cache_masp_data_on_tx_result(namada, &res, &masp_section).await;
        }
    }
    // NOTE that the tx could fail when its submission epoch doesn't match
    // construction epoch

    Ok(())
}

pub async fn submit_init_proposal<N: Namada>(
    namada: &N,
    args: args::InitProposal,
) -> Result<(), error::Error>
where
    <N::Client as namada_sdk::io::Client>::Error: std::fmt::Display,
{
    let current_epoch = rpc::query_and_print_epoch(namada).await;
    let governance_parameters =
        rpc::query_governance_parameters(namada.client()).await;
    let (proposal_tx_data, proposal_author) = if args.is_pgf_funding {
        let proposal =
            PgfFundingProposal::try_from(args.proposal_data.as_ref())
                .map_err(|e| {
                    error::TxSubmitError::FailedGovernaneProposalDeserialize(
                        e.to_string(),
                    )
                })?
                .validate(&governance_parameters, current_epoch, args.tx.force)
                .map_err(|e| {
                    error::TxSubmitError::InvalidProposal(e.to_string())
                })?;
        let proposal_author = proposal.proposal.author.clone();

        (
            tx::build_pgf_funding_proposal(namada, &args, proposal).await?,
            proposal_author,
        )
    } else if args.is_pgf_stewards {
        let proposal = PgfStewardProposal::try_from(
            args.proposal_data.as_ref(),
        )
        .map_err(|e| {
            error::TxSubmitError::FailedGovernaneProposalDeserialize(
                e.to_string(),
            )
        })?;
        let author_balance = namada_sdk::rpc::get_token_balance(
            namada.client(),
            &namada.native_token(),
            &proposal.proposal.author,
            None,
        )
        .await
        .unwrap();
        let proposal = proposal
            .validate(
                &governance_parameters,
                current_epoch,
                author_balance,
                args.tx.force,
            )
            .map_err(|e| {
                error::TxSubmitError::InvalidProposal(e.to_string())
            })?;
        let proposal_author = proposal.proposal.author.clone();

        (
            tx::build_pgf_stewards_proposal(namada, &args, proposal).await?,
            proposal_author,
        )
    } else {
        let proposal = DefaultProposal::try_from(args.proposal_data.as_ref())
            .map_err(|e| {
            error::TxSubmitError::FailedGovernaneProposalDeserialize(
                e.to_string(),
            )
        })?;
        let author_balance = namada_sdk::rpc::get_token_balance(
            namada.client(),
            &namada.native_token(),
            &proposal.proposal.author,
            None,
        )
        .await
        .unwrap();
        let proposal = proposal
            .validate(
                &governance_parameters,
                current_epoch,
                author_balance,
                args.tx.force,
            )
            .map_err(|e| {
                error::TxSubmitError::InvalidProposal(e.to_string())
            })?;
        let proposal_author = proposal.proposal.author.clone();

        (
            tx::build_default_proposal(namada, &args, proposal).await?,
            proposal_author,
        )
    };

    if args.tx.dump_tx || args.tx.dump_wrapper_tx {
        tx::dump_tx(namada.io(), &args.tx, proposal_tx_data.0)?;
    } else {
        batch_opt_reveal_pk_and_submit(
            namada,
            &args.tx,
            &[&proposal_author],
            proposal_tx_data,
        )
        .await?;
    }

    Ok(())
}

pub async fn submit_vote_proposal<N: Namada>(
    namada: &N,
    args: args::VoteProposal,
) -> Result<(), error::Error>
where
    <N::Client as namada_sdk::io::Client>::Error: std::fmt::Display,
{
    let submit_vote_proposal_data = args.build(namada).await?;

    if args.tx.dump_tx || args.tx.dump_wrapper_tx {
        tx::dump_tx(namada.io(), &args.tx, submit_vote_proposal_data.0)?;
    } else {
        batch_opt_reveal_pk_and_submit(
            namada,
            &args.tx,
            &[&args.voter_address],
            submit_vote_proposal_data,
        )
        .await?;
    }

    Ok(())
}

pub async fn submit_reveal_pk<N: Namada>(
    namada: &N,
    args: args::RevealPk,
) -> Result<(), error::Error>
where
    <N::Client as namada_sdk::io::Client>::Error: std::fmt::Display,
{
    if args.tx.dump_tx || args.tx.dump_wrapper_tx {
        let tx_data =
            tx::build_reveal_pk(namada, &args.tx, &args.public_key).await?;
        tx::dump_tx(namada.io(), &args.tx, tx_data.0.clone())?;
    } else {
        let tx_data =
            submit_reveal_aux(namada, &args.tx, &(&args.public_key).into())
                .await?;

        if let Some((mut tx, signing_data)) = tx_data {
            sign(namada, &mut tx, &args.tx, signing_data).await?;
            namada.submit(tx, &args.tx).await?;
        }
    }

    Ok(())
}

pub async fn submit_bond<N: Namada>(
    namada: &N,
    args: args::Bond,
) -> Result<(), error::Error>
where
    <N::Client as namada_sdk::io::Client>::Error: std::fmt::Display,
{
    let submit_bond_tx_data = args.build(namada).await?;

    if args.tx.dump_tx || args.tx.dump_wrapper_tx {
        tx::dump_tx(namada.io(), &args.tx, submit_bond_tx_data.0)?;
    } else {
        let default_address = args.source.as_ref().unwrap_or(&args.validator);
        batch_opt_reveal_pk_and_submit(
            namada,
            &args.tx,
            &[default_address],
            submit_bond_tx_data,
        )
        .await?;
    }

    Ok(())
}

pub async fn submit_unbond<N: Namada>(
    namada: &N,
    args: args::Unbond,
) -> Result<(), error::Error>
where
    <N::Client as namada_sdk::io::Client>::Error: std::fmt::Display,
{
    let (mut tx, signing_data, latest_withdrawal_pre) =
        args.build(namada).await?;

    if args.tx.dump_tx || args.tx.dump_wrapper_tx {
        tx::dump_tx(namada.io(), &args.tx, tx)?;
    } else {
        sign(namada, &mut tx, &args.tx, signing_data).await?;
        let cmt = tx.first_commitments().unwrap().to_owned();
        let wrapper_hash = tx.wrapper_hash();
        let resp = namada.submit(tx, &args.tx).await?;

        if !(args.tx.dry_run || args.tx.dry_run_wrapper)
            && resp
                .is_applied_and_valid(wrapper_hash.as_ref(), &cmt)
                .is_some()
        {
            tx::query_unbonds(namada, args.clone(), latest_withdrawal_pre)
                .await?;
        }
    }

    Ok(())
}

pub async fn submit_withdraw<N: Namada>(
    namada: &N,
    args: args::Withdraw,
) -> Result<(), error::Error>
where
    <N::Client as namada_sdk::io::Client>::Error: std::fmt::Display,
{
    let (mut tx, signing_data) = args.build(namada).await?;

    if args.tx.dump_tx || args.tx.dump_wrapper_tx {
        tx::dump_tx(namada.io(), &args.tx, tx)?;
    } else {
        sign(namada, &mut tx, &args.tx, signing_data).await?;

        namada.submit(tx, &args.tx).await?;
    }

    Ok(())
}

pub async fn submit_claim_rewards<N: Namada>(
    namada: &N,
    args: args::ClaimRewards,
) -> Result<(), error::Error>
where
    <N::Client as namada_sdk::io::Client>::Error: std::fmt::Display,
{
    let (mut tx, signing_data) = args.build(namada).await?;

    if args.tx.dump_tx || args.tx.dump_wrapper_tx {
        tx::dump_tx(namada.io(), &args.tx, tx)?;
    } else {
        sign(namada, &mut tx, &args.tx, signing_data).await?;

        namada.submit(tx, &args.tx).await?;
    }

    Ok(())
}

pub async fn submit_redelegate<N: Namada>(
    namada: &N,
    args: args::Redelegate,
) -> Result<(), error::Error>
where
    <N::Client as namada_sdk::io::Client>::Error: std::fmt::Display,
{
    let (mut tx, signing_data) = args.build(namada).await?;

    if args.tx.dump_tx || args.tx.dump_wrapper_tx {
        tx::dump_tx(namada.io(), &args.tx, tx)?;
    } else {
        sign(namada, &mut tx, &args.tx, signing_data).await?;

        namada.submit(tx, &args.tx).await?;
    }

    Ok(())
}

pub async fn submit_validator_commission_change<N: Namada>(
    namada: &N,
    args: args::CommissionRateChange,
) -> Result<(), error::Error>
where
    <N::Client as namada_sdk::io::Client>::Error: std::fmt::Display,
{
    let (mut tx, signing_data) = args.build(namada).await?;

    if args.tx.dump_tx || args.tx.dump_wrapper_tx {
        tx::dump_tx(namada.io(), &args.tx, tx)?;
    } else {
        sign(namada, &mut tx, &args.tx, signing_data).await?;

        namada.submit(tx, &args.tx).await?;
    }

    Ok(())
}

pub async fn submit_validator_metadata_change<N: Namada>(
    namada: &N,
    args: args::MetaDataChange,
) -> Result<(), error::Error>
where
    <N::Client as namada_sdk::io::Client>::Error: std::fmt::Display,
{
    let (mut tx, signing_data) = args.build(namada).await?;

    if args.tx.dump_tx || args.tx.dump_wrapper_tx {
        tx::dump_tx(namada.io(), &args.tx, tx)?;
    } else {
        sign(namada, &mut tx, &args.tx, signing_data).await?;

        namada.submit(tx, &args.tx).await?;
    }

    Ok(())
}

pub async fn submit_unjail_validator<N: Namada>(
    namada: &N,
    args: args::TxUnjailValidator,
) -> Result<(), error::Error>
where
    <N::Client as namada_sdk::io::Client>::Error: std::fmt::Display,
{
    let (mut tx, signing_data) = args.build(namada).await?;

    if args.tx.dump_tx || args.tx.dump_wrapper_tx {
        tx::dump_tx(namada.io(), &args.tx, tx)?;
    } else {
        sign(namada, &mut tx, &args.tx, signing_data).await?;

        namada.submit(tx, &args.tx).await?;
    }

    Ok(())
}

pub async fn submit_deactivate_validator<N: Namada>(
    namada: &N,
    args: args::TxDeactivateValidator,
) -> Result<(), error::Error>
where
    <N::Client as namada_sdk::io::Client>::Error: std::fmt::Display,
{
    let (mut tx, signing_data) = args.build(namada).await?;

    if args.tx.dump_tx || args.tx.dump_wrapper_tx {
        tx::dump_tx(namada.io(), &args.tx, tx)?;
    } else {
        sign(namada, &mut tx, &args.tx, signing_data).await?;

        namada.submit(tx, &args.tx).await?;
    }

    Ok(())
}

pub async fn submit_reactivate_validator<N: Namada>(
    namada: &N,
    args: args::TxReactivateValidator,
) -> Result<(), error::Error>
where
    <N::Client as namada_sdk::io::Client>::Error: std::fmt::Display,
{
    let (mut tx, signing_data) = args.build(namada).await?;

    if args.tx.dump_tx || args.tx.dump_wrapper_tx {
        tx::dump_tx(namada.io(), &args.tx, tx)?;
    } else {
        sign(namada, &mut tx, &args.tx, signing_data).await?;

        namada.submit(tx, &args.tx).await?;
    }

    Ok(())
}

pub async fn submit_update_steward_commission<N: Namada>(
    namada: &N,
    args: args::UpdateStewardCommission,
) -> Result<(), error::Error>
where
    <N::Client as namada_sdk::io::Client>::Error: std::fmt::Display,
{
    let (mut tx, signing_data) = args.build(namada).await?;

    if args.tx.dump_tx || args.tx.dump_wrapper_tx {
        tx::dump_tx(namada.io(), &args.tx, tx)?;
    } else {
        sign(namada, &mut tx, &args.tx, signing_data).await?;

        namada.submit(tx, &args.tx).await?;
    }

    Ok(())
}

pub async fn submit_resign_steward<N: Namada>(
    namada: &N,
    args: args::ResignSteward,
) -> Result<(), error::Error>
where
    <N::Client as namada_sdk::io::Client>::Error: std::fmt::Display,
{
    let (mut tx, signing_data) = args.build(namada).await?;

    if args.tx.dump_tx || args.tx.dump_wrapper_tx {
        tx::dump_tx(namada.io(), &args.tx, tx)?;
    } else {
        sign(namada, &mut tx, &args.tx, signing_data).await?;

        namada.submit(tx, &args.tx).await?;
    }

    Ok(())
}

/// Save accounts initialized from a tx into the wallet, if any.
pub async fn save_initialized_accounts(
    namada: &impl Namada,
    args: &args::Tx,
    initialized_accounts: Vec<Address>,
) {
    tx::save_initialized_accounts(namada, args, initialized_accounts).await
}

/// Broadcast a transaction to be included in the blockchain and checks that
/// the tx has been successfully included into the mempool of a validator
///
/// In the case of errors in any of those stages, an error message is returned
pub async fn broadcast_tx(
    namada: &impl Namada,
    to_broadcast: &TxBroadcastData,
) -> Result<Response, error::Error> {
    tx::broadcast_tx(namada, to_broadcast).await
}

/// Broadcast a transaction to be included in the blockchain.
///
/// Checks that
/// 1. The tx has been successfully included into the mempool of a validator
/// 2. The tx has been included on the blockchain
///
/// In the case of errors in any of those stages, an error message is returned
pub async fn submit_tx(
    namada: &impl Namada,
    to_broadcast: TxBroadcastData,
) -> Result<TxResponse, error::Error> {
    tx::submit_tx(namada, to_broadcast).await
}

/// Generate MASP transaction and output it
pub async fn gen_ibc_shielding_transfer(
    context: &impl Namada,
    args: args::GenIbcShieldingTransfer,
) -> Result<(), error::Error> {
    let output_folder = args.output_folder.clone();

    if let Some(masp_tx) = tx::gen_ibc_shielding_transfer(context, args).await?
    {
        let tx_id = masp_tx.txid().to_string();
        let filename = format!("ibc_masp_tx_{}.memo", tx_id);
        let output_path = match output_folder {
            Some(path) => path.join(filename),
            None => filename.into(),
        };
        let mut out = File::create(&output_path)
            .expect("Creating a new file for IBC MASP transaction failed.");
        let bytes = convert_masp_tx_to_ibc_memo(&masp_tx);
        out.write_all(bytes.as_bytes())
            .expect("Writing IBC MASP transaction file failed.");
        println!(
            "Output IBC shielding transfer for {tx_id} to {}",
            output_path.to_string_lossy()
        );
    } else {
        eprintln!("No shielded transfer for this IBC transfer.")
    }
    Ok(())
}

// Pre-cache the data for the provided MASP transaction. Log an error on
// failure.
async fn pre_cache_masp_data(namada: &impl Namada, masp_tx: &MaspTransaction) {
    if let Err(e) = namada
        .shielded_mut()
        .await
        .pre_cache_transaction(masp_tx)
        .await
    {
        // Just display the error but do not propagate it
        edisplay_line!(namada.io(), "Failed to pre-cache masp data: {}.", e);
    }
}

// Check the result of a transaction and pre-cache the masp data accordingly
async fn pre_cache_masp_data_on_tx_result(
    namada: &impl Namada,
    tx_result: &ProcessTxResponse,
    masp_tx: &MaspTransaction,
) {
    match tx_result {
        ProcessTxResponse::Applied(resp) => {
            if let Some(InnerTxResult::Success(_)) =
                // If we have the masp data in an ibc transfer it
                // means we are unshielding, so there's no reveal pk
                // tx in the batch which contains only the ibc tx
                resp.batch_result().first().map(|(_, res)| res)
            {
                pre_cache_masp_data(namada, masp_tx).await;
            }
        }
        ProcessTxResponse::Broadcast(_) => {
            pre_cache_masp_data(namada, masp_tx).await;
        }
        // Do not pre-cache when dry-running
        ProcessTxResponse::DryRun(_) => {}
    }
}
