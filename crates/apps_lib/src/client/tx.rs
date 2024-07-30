use std::fs::File;
use std::io::Write;

use borsh::BorshDeserialize;
use borsh_ext::BorshSerializeExt;
use ledger_namada_rs::{BIP44Path, NamadaApp};
use ledger_transport_hid::hidapi::HidApi;
use ledger_transport_hid::TransportNativeHID;
use namada_sdk::address::{Address, ImplicitAddress};
use namada_sdk::args::TxBecomeValidator;
use namada_sdk::collections::HashSet;
use namada_sdk::governance::cli::onchain::{
    DefaultProposal, PgfFundingProposal, PgfStewardProposal,
};
use namada_sdk::ibc::convert_masp_tx_to_ibc_memo;
use namada_sdk::io::Io;
use namada_sdk::key::*;
use namada_sdk::rpc::{InnerTxResult, TxBroadcastData, TxResponse};
use namada_sdk::state::EPOCH_SWITCH_BLOCKS_DELAY;
use namada_sdk::tx::data::compute_inner_tx_hash;
use namada_sdk::tx::{CompressedAuthorization, Section, Signer, Tx};
use namada_sdk::wallet::alias::{validator_address, validator_consensus_key};
use namada_sdk::wallet::{Wallet, WalletIo};
use namada_sdk::{display_line, edisplay_line, error, signing, tx, Namada};
use rand::rngs::OsRng;
use tokio::sync::RwLock;

use super::rpc;
use crate::cli::{args, safe_exit};
use crate::client::tx::signing::{default_sign, SigningTxData};
use crate::client::tx::tx::ProcessTxResponse;
use crate::config::TendermintMode;
use crate::facade::tendermint_rpc::endpoint::broadcast::tx_sync::Response;
use crate::tendermint_node;
use crate::wallet::{gen_validator_keys, read_and_confirm_encryption_password};

/// Wrapper around `signing::aux_signing_data` that stores the optional
/// disposable address to the wallet
pub async fn aux_signing_data(
    context: &impl Namada,
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

pub async fn with_hardware_wallet<'a, U: WalletIo + Clone>(
    mut tx: Tx,
    pubkey: common::PublicKey,
    parts: HashSet<signing::Signable>,
    (wallet, app): (&RwLock<Wallet<U>>, &NamadaApp<TransportNativeHID>),
) -> Result<Tx, error::Error> {
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
    let response = app
        .sign(&path, &tx.serialize_to_vec())
        .await
        .map_err(|err| error::Error::Other(err.to_string()))?;
    // Sign the raw header if that is requested
    if parts.contains(&signing::Signable::RawHeader) {
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
    if parts.contains(&signing::Signable::FeeHeader) {
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
        // Setup a reusable context for signing transactions using the Ledger
        let hidapi = HidApi::new().map_err(|err| {
            error::Error::Other(format!("Failed to create Hidapi: {}", err))
        })?;
        let app = NamadaApp::new(TransportNativeHID::new(&hidapi).map_err(
            |err| {
                error::Error::Other(format!(
                    "Unable to connect to Ledger: {}",
                    err
                ))
            },
        )?);
        let with_hw_data = (context.wallet_lock(), &app);
        // Finally, begin the signing with the Ledger as backup
        context
            .sign(
                tx,
                args,
                signing_data,
                with_hardware_wallet::<N::WalletUtils>,
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
    args: args::Tx,
    address: &Address,
) -> Result<(), error::Error> {
    if args.dump_tx {
        return Ok(());
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
                 {address}..."
            );
            let (mut tx, signing_data) =
                tx::build_reveal_pk(context, &args, &public_key).await?;

            sign(context, &mut tx, &args, signing_data).await?;

            context.submit(tx, &args).await?;
        }
    }

    Ok(())
}

pub async fn submit_bridge_pool_tx<N: Namada>(
    namada: &N,
    args: args::EthereumBridgePool,
) -> Result<(), error::Error> {
    let tx_args = args.tx.clone();
    let (mut tx, signing_data) = args.clone().build(namada).await?;

    if args.tx.dump_tx {
        tx::dump_tx(namada.io(), &args.tx, tx);
    } else {
        submit_reveal_aux(namada, tx_args.clone(), &args.sender).await?;

        sign(namada, &mut tx, &tx_args, signing_data).await?;

        namada.submit(tx, &tx_args).await?;
    }

    Ok(())
}

pub async fn submit_custom<N: Namada>(
    namada: &N,
    args: args::TxCustom,
) -> Result<(), error::Error>
where
    <N::Client as namada_sdk::queries::Client>::Error: std::fmt::Display,
{
    submit_reveal_aux(namada, args.tx.clone(), &args.owner).await?;

    let (mut tx, signing_data) = args.build(namada).await?;

    if args.tx.dump_tx {
        tx::dump_tx(namada.io(), &args.tx, tx);
    } else {
        sign(namada, &mut tx, &args.tx, signing_data).await?;

        namada.submit(tx, &args.tx).await?;
    }

    Ok(())
}

pub async fn submit_update_account<N: Namada>(
    namada: &N,
    args: args::TxUpdateAccount,
) -> Result<(), error::Error>
where
    <N::Client as namada_sdk::queries::Client>::Error: std::fmt::Display,
{
    let (mut tx, signing_data) = args.build(namada).await?;

    if args.tx.dump_tx {
        tx::dump_tx(namada.io(), &args.tx, tx);
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
    <N::Client as namada_sdk::queries::Client>::Error: std::fmt::Display,
{
    let (mut tx, signing_data) = tx::build_init_account(namada, &args).await?;

    if args.tx.dump_tx {
        tx::dump_tx(namada.io(), &args.tx, tx);
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

    if args.tx.dump_tx {
        tx::dump_tx(namada.io(), &args.tx, tx);
    } else {
        sign(namada, &mut tx, &args.tx, signing_data).await?;
        let cmt = tx.first_commitments().unwrap().to_owned();
        let wrapper_hash = tx.wrapper_hash();
        let resp = namada.submit(tx, &args.tx).await?;

        if !args.tx.dry_run {
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

    if args.tx.dump_tx {
        tx::dump_tx(namada.io(), &args.tx, tx);
    } else {
        sign(namada, &mut tx, &args.tx, signing_data).await?;
        let cmt = tx.first_commitments().unwrap().to_owned();
        let wrapper_hash = tx.wrapper_hash();
        let resp = namada.submit(tx, &args.tx).await?;

        if args.tx.dry_run {
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
            display_line!(
                namada.io(),
                "Transaction failed. No key or addresses have been saved."
            );
            safe_exit(1)
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

    if tx_args.dry_run {
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

    submit_reveal_aux(
        namada,
        args.tx.clone(),
        &args
            .data
            .first()
            .ok_or_else(|| {
                error::Error::Other("Missing transfer data".to_string())
            })?
            .source,
    )
    .await?;

    let (mut tx, signing_data) = args.clone().build(namada).await?;

    if args.tx.dump_tx {
        tx::dump_tx(namada.io(), &args.tx, tx);
    } else {
        sign(namada, &mut tx, &args.tx, signing_data).await?;
        namada.submit(tx, &args.tx).await?;
    }

    Ok(())
}

pub async fn submit_shielded_transfer(
    namada: &impl Namada,
    args: args::TxShieldedTransfer,
) -> Result<(), error::Error> {
    let (mut tx, signing_data) = args.clone().build(namada).await?;

    if args.tx.dump_tx {
        tx::dump_tx(namada.io(), &args.tx, tx);
    } else {
        sign(namada, &mut tx, &args.tx, signing_data).await?;
        namada.submit(tx, &args.tx).await?;
    }
    Ok(())
}

pub async fn submit_shielding_transfer(
    namada: &impl Namada,
    args: args::TxShieldingTransfer,
) -> Result<(), error::Error> {
    // Repeat once if the tx fails on a crossover of an epoch
    for _ in 0..2 {
        let (mut tx, signing_data, tx_epoch) =
            args.clone().build(namada).await?;

        if args.tx.dump_tx {
            tx::dump_tx(namada.io(), &args.tx, tx);
            break;
        } else {
            sign(namada, &mut tx, &args.tx, signing_data).await?;
            let cmt_hash = tx.first_commitments().unwrap().get_hash();
            let wrapper_hash = tx.wrapper_hash();
            let result = namada.submit(tx, &args.tx).await?;
            match result {
                ProcessTxResponse::Applied(resp) if
                    // If a transaction is rejected by a VP
                    matches!(
                        resp.batch_result().get(&compute_inner_tx_hash(
                            wrapper_hash.as_ref(),
                            either::Left(&cmt_hash)
                        )),
                        Some(InnerTxResult::VpsRejected(_))
                    ) =>
                {
                    let submission_masp_epoch = rpc::query_and_print_masp_epoch(namada).await;
                    // And its submission epoch doesn't match construction epoch
                    if tx_epoch != submission_masp_epoch {
                        // Then we probably straddled an epoch boundary. Let's retry...
                        edisplay_line!(namada.io(),
                            "Shielding transaction rejected and this may be due to the \
                            epoch changing. Attempting to resubmit transaction.",
                        );
                        continue;
                    }
                },
                // Otherwise either the transaction was successful or it will not
                // benefit from resubmission
                _ => break,
            }
        }
    }
    Ok(())
}

pub async fn submit_unshielding_transfer(
    namada: &impl Namada,
    args: args::TxUnshieldingTransfer,
) -> Result<(), error::Error> {
    let (mut tx, signing_data) = args.clone().build(namada).await?;

    if args.tx.dump_tx {
        tx::dump_tx(namada.io(), &args.tx, tx);
    } else {
        sign(namada, &mut tx, &args.tx, signing_data).await?;
        namada.submit(tx, &args.tx).await?;
    }
    Ok(())
}

pub async fn submit_ibc_transfer<N: Namada>(
    namada: &N,
    args: args::TxIbcTransfer,
) -> Result<(), error::Error>
where
    <N::Client as namada_sdk::queries::Client>::Error: std::fmt::Display,
{
    submit_reveal_aux(
        namada,
        args.tx.clone(),
        &args.source.effective_address(),
    )
    .await?;
    let (mut tx, signing_data, _) = args.build(namada).await?;

    if args.tx.dump_tx {
        tx::dump_tx(namada.io(), &args.tx, tx);
    } else {
        sign(namada, &mut tx, &args.tx, signing_data).await?;

        namada.submit(tx, &args.tx).await?;
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
    <N::Client as namada_sdk::queries::Client>::Error: std::fmt::Display,
{
    let current_epoch = rpc::query_and_print_epoch(namada).await;
    let governance_parameters =
        rpc::query_governance_parameters(namada.client()).await;
    let (mut tx_builder, signing_data) = if args.is_pgf_funding {
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

        submit_reveal_aux(namada, args.tx.clone(), &proposal.proposal.author)
            .await?;

        tx::build_pgf_funding_proposal(namada, &args, proposal).await?
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

        submit_reveal_aux(namada, args.tx.clone(), &proposal.proposal.author)
            .await?;

        tx::build_pgf_stewards_proposal(namada, &args, proposal).await?
    } else {
        let proposal = DefaultProposal::try_from(args.proposal_data.as_ref())
            .map_err(|e| {
            error::TxSubmitError::FailedGovernaneProposalDeserialize(
                e.to_string(),
            )
        })?;
        let author_balane = namada_sdk::rpc::get_token_balance(
            namada.client(),
            &namada.native_token(),
            &proposal.proposal.author,
        )
        .await
        .unwrap();
        let proposal = proposal
            .validate(
                &governance_parameters,
                current_epoch,
                author_balane,
                args.tx.force,
            )
            .map_err(|e| {
                error::TxSubmitError::InvalidProposal(e.to_string())
            })?;

        submit_reveal_aux(namada, args.tx.clone(), &proposal.proposal.author)
            .await?;

        tx::build_default_proposal(namada, &args, proposal).await?
    };

    if args.tx.dump_tx {
        tx::dump_tx(namada.io(), &args.tx, tx_builder);
    } else {
        sign(namada, &mut tx_builder, &args.tx, signing_data).await?;

        namada.submit(tx_builder, &args.tx).await?;
    }

    Ok(())
}

pub async fn submit_vote_proposal<N: Namada>(
    namada: &N,
    args: args::VoteProposal,
) -> Result<(), error::Error>
where
    <N::Client as namada_sdk::queries::Client>::Error: std::fmt::Display,
{
    let (mut tx_builder, signing_data) = args.build(namada).await?;

    if args.tx.dump_tx {
        tx::dump_tx(namada.io(), &args.tx, tx_builder);
    } else {
        sign(namada, &mut tx_builder, &args.tx, signing_data).await?;

        namada.submit(tx_builder, &args.tx).await?;
    }

    Ok(())
}

pub async fn sign_tx<N: Namada>(
    namada: &N,
    args::SignTx {
        tx: tx_args,
        tx_data,
        owner,
    }: args::SignTx,
) -> Result<(), error::Error>
where
    <N::Client as namada_sdk::queries::Client>::Error: std::fmt::Display,
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

pub async fn submit_reveal_pk<N: Namada>(
    namada: &N,
    args: args::RevealPk,
) -> Result<(), error::Error>
where
    <N::Client as namada_sdk::queries::Client>::Error: std::fmt::Display,
{
    submit_reveal_aux(namada, args.tx, &(&args.public_key).into()).await?;

    Ok(())
}

pub async fn submit_bond<N: Namada>(
    namada: &N,
    args: args::Bond,
) -> Result<(), error::Error>
where
    <N::Client as namada_sdk::queries::Client>::Error: std::fmt::Display,
{
    let default_address = args.source.clone().unwrap_or(args.validator.clone());
    submit_reveal_aux(namada, args.tx.clone(), &default_address).await?;

    let (mut tx, signing_data) = args.build(namada).await?;

    if args.tx.dump_tx {
        tx::dump_tx(namada.io(), &args.tx, tx);
    } else {
        sign(namada, &mut tx, &args.tx, signing_data).await?;

        namada.submit(tx, &args.tx).await?;
    }

    Ok(())
}

pub async fn submit_unbond<N: Namada>(
    namada: &N,
    args: args::Unbond,
) -> Result<(), error::Error>
where
    <N::Client as namada_sdk::queries::Client>::Error: std::fmt::Display,
{
    let (mut tx, signing_data, latest_withdrawal_pre) =
        args.build(namada).await?;

    if args.tx.dump_tx {
        tx::dump_tx(namada.io(), &args.tx, tx);
    } else {
        sign(namada, &mut tx, &args.tx, signing_data).await?;
        let cmt = tx.first_commitments().unwrap().to_owned();
        let wrapper_hash = tx.wrapper_hash();
        let resp = namada.submit(tx, &args.tx).await?;

        if !args.tx.dry_run
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
    <N::Client as namada_sdk::queries::Client>::Error: std::fmt::Display,
{
    let (mut tx, signing_data) = args.build(namada).await?;

    if args.tx.dump_tx {
        tx::dump_tx(namada.io(), &args.tx, tx);
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
    <N::Client as namada_sdk::queries::Client>::Error: std::fmt::Display,
{
    let (mut tx, signing_data) = args.build(namada).await?;

    if args.tx.dump_tx {
        tx::dump_tx(namada.io(), &args.tx, tx);
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
    <N::Client as namada_sdk::queries::Client>::Error: std::fmt::Display,
{
    let (mut tx, signing_data) = args.build(namada).await?;

    if args.tx.dump_tx {
        tx::dump_tx(namada.io(), &args.tx, tx);
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
    <N::Client as namada_sdk::queries::Client>::Error: std::fmt::Display,
{
    let (mut tx, signing_data) = args.build(namada).await?;

    if args.tx.dump_tx {
        tx::dump_tx(namada.io(), &args.tx, tx);
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
    <N::Client as namada_sdk::queries::Client>::Error: std::fmt::Display,
{
    let (mut tx, signing_data) = args.build(namada).await?;

    if args.tx.dump_tx {
        tx::dump_tx(namada.io(), &args.tx, tx);
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
    <N::Client as namada_sdk::queries::Client>::Error: std::fmt::Display,
{
    let (mut tx, signing_data) = args.build(namada).await?;

    if args.tx.dump_tx {
        tx::dump_tx(namada.io(), &args.tx, tx);
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
    <N::Client as namada_sdk::queries::Client>::Error: std::fmt::Display,
{
    let (mut tx, signing_data) = args.build(namada).await?;

    if args.tx.dump_tx {
        tx::dump_tx(namada.io(), &args.tx, tx);
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
    <N::Client as namada_sdk::queries::Client>::Error: std::fmt::Display,
{
    let (mut tx, signing_data) = args.build(namada).await?;

    if args.tx.dump_tx {
        tx::dump_tx(namada.io(), &args.tx, tx);
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
    <N::Client as namada_sdk::queries::Client>::Error: std::fmt::Display,
{
    let (mut tx, signing_data) = args.build(namada).await?;

    if args.tx.dump_tx {
        tx::dump_tx(namada.io(), &args.tx, tx);
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
    <N::Client as namada_sdk::queries::Client>::Error: std::fmt::Display,
{
    let (mut tx, signing_data) = args.build(namada).await?;

    if args.tx.dump_tx {
        tx::dump_tx(namada.io(), &args.tx, tx);
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
/// 2. The tx with encrypted payload has been included on the blockchain
/// 3. The decrypted payload of the tx has been included on the blockchain.
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
    if let Some(masp_tx) =
        tx::gen_ibc_shielding_transfer(context, args.clone()).await?
    {
        let tx_id = masp_tx.txid().to_string();
        let filename = format!("ibc_masp_tx_{}.memo", tx_id);
        let output_path = match &args.output_folder {
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
