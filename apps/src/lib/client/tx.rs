use std::collections::HashSet;
use std::fs::File;
use std::io::Write;

use borsh::BorshDeserialize;
use borsh_ext::BorshSerializeExt;
use ledger_namada_rs::{BIP44Path, NamadaApp};
use ledger_transport_hid::hidapi::HidApi;
use ledger_transport_hid::TransportNativeHID;
use namada::core::ledger::governance::cli::offline::{
    OfflineProposal, OfflineSignedProposal, OfflineVote,
};
use namada::core::ledger::governance::cli::onchain::{
    DefaultProposal, PgfFundingProposal, PgfStewardProposal,
};
use namada::core::ledger::governance::storage::vote::ProposalVote;
use namada::core::ledger::storage::EPOCH_SWITCH_BLOCKS_DELAY;
use namada::ibc::apps::transfer::types::Memo;
use namada::proto::{CompressedSignature, Section, Signer, Tx};
use namada::types::address::{Address, ImplicitAddress};
use namada::types::dec::Dec;
use namada::types::io::Io;
use namada::types::key::{self, *};
use namada::types::transaction::pos::{BecomeValidator, ConsensusKeyChange};
use namada_sdk::rpc::{InnerTxResult, TxBroadcastData, TxResponse};
use namada_sdk::wallet::alias::validator_consensus_key;
use namada_sdk::wallet::{Wallet, WalletIo};
use namada_sdk::{display_line, edisplay_line, error, signing, tx, Namada};
use rand::rngs::OsRng;
use tokio::sync::RwLock;

use super::rpc;
use crate::cli::{args, safe_exit};
use crate::client::rpc::query_wasm_code_hash;
use crate::client::tx::signing::{
    default_sign, init_validator_signing_data, SigningTxData,
};
use crate::client::tx::tx::ProcessTxResponse;
use crate::config::TendermintMode;
use crate::facade::tendermint_rpc::endpoint::broadcast::tx_sync::Response;
use crate::node::ledger::tendermint_node;
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
        let compressed = CompressedSignature {
            targets: response.raw_indices,
            signer: Signer::PubKeys(vec![pubkey]),
            signatures: [(0, signature)].into(),
        };
        // Expand out the signature before adding it to the
        // transaction
        tx.add_section(Section::Signature(compressed.expand(&tx)));
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
        let compressed = CompressedSignature {
            targets: response.wrapper_indices,
            signer: Signer::PubKeys(vec![pubkey]),
            signatures: [(0, signature)].into(),
        };
        // Expand out the signature before adding it to the
        // transaction
        tx.add_section(Section::Signature(compressed.expand(&tx)));
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

        if tx::is_reveal_pk_needed(context.client(), address, args.force)
            .await?
        {
            println!(
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
    <N::Client as namada::ledger::queries::Client>::Error: std::fmt::Display,
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
    <N::Client as namada::ledger::queries::Client>::Error: std::fmt::Display,
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
    <N::Client as namada::ledger::queries::Client>::Error: std::fmt::Display,
{
    let (mut tx, signing_data) = tx::build_init_account(namada, &args).await?;

    if args.tx.dump_tx {
        tx::dump_tx(namada.io(), &args.tx, tx);
    } else {
        sign(namada, &mut tx, &args.tx, signing_data).await?;

        let response = namada.submit(tx, &args.tx).await?;
        if let Some(result) = response.is_applied_and_valid() {
            return Ok(result.initialized_accounts.first().cloned());
        }
    }

    Ok(None)
}

pub async fn submit_change_consensus_key(
    namada: &impl Namada,
    config: &mut crate::config::Config,
    args::ConsensusKeyChange {
        tx: tx_args,
        validator,
        consensus_key,
        unsafe_dont_encrypt,
        tx_code_path: _,
    }: args::ConsensusKeyChange,
) -> Result<(), error::Error> {
    let tx_args = args::Tx {
        chain_id: tx_args
            .clone()
            .chain_id
            .or_else(|| Some(config.ledger.chain_id.clone())),
        ..tx_args.clone()
    };

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
                read_and_confirm_encryption_password(unsafe_dont_encrypt);
            wallet
                .gen_store_secret_key(
                    // Note that TM only allows ed25519 for consensus key
                    SchemeType::Ed25519,
                    Some(consensus_key_alias.clone()),
                    tx_args.wallet_alias_force,
                    password,
                    &mut OsRng,
                )
                .expect("Key generation should not fail.")
                .1
                .ref_to()
        });
    // To avoid wallet deadlocks in following operations
    drop(wallet);

    // Check that the new consensus key is unique
    let consensus_keys = rpc::query_consensus_keys(namada.client()).await;

    if consensus_keys.contains(&new_key) {
        edisplay_line!(namada.io(), "The consensus key is already being used.");
        safe_exit(1)
    }

    let tx_code_hash =
        query_wasm_code_hash(namada, args::TX_CHANGE_CONSENSUS_KEY_WASM)
            .await
            .unwrap();

    let chain_id = tx_args.chain_id.clone().unwrap();
    let mut tx = Tx::new(chain_id, tx_args.expiration);

    let data = ConsensusKeyChange {
        validator: validator.clone(),
        consensus_key: new_key.clone(),
    };

    tx.add_code_from_hash(
        tx_code_hash,
        Some(args::TX_CHANGE_CONSENSUS_KEY_WASM.to_string()),
    )
    .add_data(data);

    let signing_data =
        init_validator_signing_data(namada, &tx_args, vec![new_key]).await?;

    tx::prepare_tx(
        namada,
        &tx_args,
        &mut tx,
        signing_data.fee_payer.clone(),
        None,
    )
    .await?;

    if tx_args.dump_tx {
        tx::dump_tx(namada.io(), &tx_args, tx);
    } else {
        sign(namada, &mut tx, &tx_args, signing_data).await?;
        let resp = namada.submit(tx, &tx_args).await?;

        if !tx_args.dry_run {
            if resp.is_applied_and_valid().is_some() {
                namada.wallet_mut().await.save().unwrap_or_else(|err| {
                    edisplay_line!(namada.io(), "{}", err)
                });

                display_line!(
                    namada.io(),
                    "New consensus key stored with alias \
                     \"{consensus_key_alias}\". It will become active \
                     {EPOCH_SWITCH_BLOCKS_DELAY} blocks before pipeline \
                     offset from the current epoch, at which point you'll \
                     need to give the new key to CometBFT in order to be able \
                     to sign with it in consensus.",
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
        website,
        description,
        discord_handle,
        avatar,
        unsafe_dont_encrypt,
        tx_code_path,
    }: args::TxBecomeValidator,
) -> Result<(), error::Error> {
    let tx_args = args::Tx {
        chain_id: tx_args
            .clone()
            .chain_id
            .or_else(|| Some(config.ledger.chain_id.clone())),
        ..tx_args.clone()
    };

    // Check that the address is established
    if !address.is_established() {
        edisplay_line!(
            namada.io(),
            "The given address {address} is not established. Only an \
             established address can become a validator.",
        );
        if !tx_args.force {
            safe_exit(1)
        }
    };

    // Check that the address is not already a validator
    if rpc::is_validator(namada.client(), &address).await {
        edisplay_line!(
            namada.io(),
            "The given address {address} is already a validator",
        );
        if !tx_args.force {
            safe_exit(1)
        }
    };

    // If the address is not yet a validator, it cannot have self-bonds, but it
    // may have delegations. It has to unbond those before it can become a
    // validator.
    if rpc::has_bonds(namada.client(), &address).await {
        edisplay_line!(
            namada.io(),
            "The given address {address} has delegations and therefore cannot \
             become a validator. To become a validator, you have to unbond \
             your delegations first.",
        );
        if !tx_args.force {
            safe_exit(1)
        }
    }

    // Validate the commission rate data
    if commission_rate > Dec::one() || commission_rate < Dec::zero() {
        edisplay_line!(
            namada.io(),
            "The validator commission rate must not exceed 1.0 or 100%, and \
             it must be 0 or positive."
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
             not exceed 1.0 or 100%, and it must be 0 or positive."
        );
        if !tx_args.force {
            safe_exit(1)
        }
    }
    // Validate the email
    if email.is_empty() {
        edisplay_line!(
            namada.io(),
            "The validator email must not be an empty string."
        );
        if !tx_args.force {
            safe_exit(1)
        }
    }

    let alias = tx_args
        .initialized_account_alias
        .as_ref()
        .cloned()
        .unwrap_or_else(|| "validator".to_string());

    let validator_key_alias = format!("{}-key", alias);
    let consensus_key_alias = validator_consensus_key(&alias.clone().into());
    let protocol_key_alias = format!("{}-protocol-key", alias);
    let eth_hot_key_alias = format!("{}-eth-hot-key", alias);
    let eth_cold_key_alias = format!("{}-eth-cold-key", alias);

    let mut wallet = namada.wallet_mut().await;
    let consensus_key = consensus_key
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
                read_and_confirm_encryption_password(unsafe_dont_encrypt);
            wallet
                .gen_store_secret_key(
                    // Note that TM only allows ed25519 for consensus key
                    SchemeType::Ed25519,
                    Some(consensus_key_alias.clone().into()),
                    tx_args.wallet_alias_force,
                    password,
                    &mut OsRng,
                )
                .expect("Key generation should not fail.")
                .1
                .ref_to()
        });

    let eth_cold_pk = eth_cold_key
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
                read_and_confirm_encryption_password(unsafe_dont_encrypt);
            wallet
                .gen_store_secret_key(
                    // Note that ETH only allows secp256k1
                    SchemeType::Secp256k1,
                    Some(eth_cold_key_alias.clone()),
                    tx_args.wallet_alias_force,
                    password,
                    &mut OsRng,
                )
                .expect("Key generation should not fail.")
                .1
                .ref_to()
        });

    let eth_hot_pk = eth_hot_key
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
                read_and_confirm_encryption_password(unsafe_dont_encrypt);
            wallet
                .gen_store_secret_key(
                    // Note that ETH only allows secp256k1
                    SchemeType::Secp256k1,
                    Some(eth_hot_key_alias.clone()),
                    tx_args.wallet_alias_force,
                    password,
                    &mut OsRng,
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
        &mut *namada.wallet_mut().await,
        Some(eth_hot_pk.clone()),
        protocol_key,
        scheme,
    )
    .unwrap();
    let protocol_sk = validator_keys.get_protocol_keypair();
    let protocol_key = protocol_sk.to_public();

    // Store the protocol key in the wallet so that we can sign the tx with it
    // to verify ownership
    display_line!(namada.io(), "Storing protocol key in the wallet...");
    let password = read_and_confirm_encryption_password(unsafe_dont_encrypt);
    namada
        .wallet_mut()
        .await
        .insert_keypair(
            protocol_key_alias,
            tx_args.wallet_alias_force,
            protocol_sk.clone(),
            password,
            None,
            None,
        )
        .map_err(|err| error::Error::Other(err.to_string()))?;

    let tx_code_hash =
        query_wasm_code_hash(namada, tx_code_path.to_string_lossy())
            .await
            .unwrap();

    let chain_id = tx_args.chain_id.clone().unwrap();
    let mut tx = Tx::new(chain_id, tx_args.expiration);
    let data = BecomeValidator {
        address: address.clone(),
        consensus_key: consensus_key.clone(),
        eth_cold_key: key::secp256k1::PublicKey::try_from_pk(&eth_cold_pk)
            .unwrap(),
        eth_hot_key: key::secp256k1::PublicKey::try_from_pk(&eth_hot_pk)
            .unwrap(),
        protocol_key,
        commission_rate,
        max_commission_rate_change,
        email,
        description,
        website,
        discord_handle,
        avatar,
    };

    // Put together all the PKs that we have to sign with to verify ownership
    let account = namada_sdk::rpc::get_account_info(namada.client(), &address)
        .await?
        .unwrap_or_else(|| {
            edisplay_line!(
                namada.io(),
                "Unable to query account keys for address {address}."
            );
            safe_exit(1)
        });
    let mut all_pks: Vec<_> =
        account.public_keys_map.pk_to_idx.into_keys().collect();
    all_pks.push(consensus_key.clone());
    all_pks.push(eth_cold_pk);
    all_pks.push(eth_hot_pk);
    all_pks.push(data.protocol_key.clone());

    tx.add_code_from_hash(
        tx_code_hash,
        Some(args::TX_BECOME_VALIDATOR_WASM.to_string()),
    )
    .add_data(data);

    let signing_data =
        init_validator_signing_data(namada, &tx_args, all_pks).await?;

    tx::prepare_tx(
        namada,
        &tx_args,
        &mut tx,
        signing_data.fee_payer.clone(),
        None,
    )
    .await?;

    if tx_args.dump_tx {
        tx::dump_tx(namada.io(), &tx_args, tx);
    } else {
        sign(namada, &mut tx, &tx_args, signing_data).await?;
        let resp = namada.submit(tx, &tx_args).await?;

        if !tx_args.dry_run {
            if resp.is_applied_and_valid().is_some() {
                // add validator address and keys to the wallet
                let mut wallet = namada.wallet_mut().await;
                wallet.add_validator_data(address.clone(), validator_keys);
                wallet.save().unwrap_or_else(|err| {
                    edisplay_line!(namada.io(), "{}", err)
                });

                let tendermint_home = config.ledger.cometbft_dir();
                tendermint_node::write_validator_key(
                    &tendermint_home,
                    &wallet.find_key_by_pk(&consensus_key, None).expect(
                        "unable to find consensus key pair in the wallet",
                    ),
                )
                .unwrap();
                // To avoid wallet deadlocks in following operations
                drop(wallet);
                tendermint_node::write_validator_state(tendermint_home)
                    .unwrap();

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

                let pos_params =
                    rpc::query_pos_parameters(namada.client()).await;

                display_line!(namada.io(), "");
                display_line!(
                    namada.io(),
                    "The keys for validator \"{alias}\" were stored in the \
                     wallet:"
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
            }
        } else {
            display_line!(
                namada.io(),
                "Transaction dry run. No key or addresses have been saved."
            );
        }
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
        safe_exit(1);
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
            tx_code_path: tx_become_validator_code_path,
            unsafe_dont_encrypt,
        },
    )
    .await
}

pub async fn submit_transfer(
    namada: &impl Namada,
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

        if args.tx.dump_tx {
            tx::dump_tx(namada.io(), &args.tx, tx);
            break;
        } else {
            sign(namada, &mut tx, &args.tx, signing_data).await?;

            let result = namada.submit(tx, &args.tx).await?;

            match result {
                ProcessTxResponse::Applied(resp) if
                    // If a transaction is shielded
                    tx_epoch.is_some() &&
                    // And it is rejected by a VP
                    matches!(resp.inner_tx_result(), InnerTxResult::VpsRejected(_)) =>
                {
                    let submission_epoch = rpc::query_and_print_epoch(namada).await;
                    // And its submission epoch doesn't match construction epoch
                    if tx_epoch.unwrap() != submission_epoch {
                        // Then we probably straddled an epoch boundary. Let's retry...
                        edisplay_line!(namada.io(),
                            "MASP transaction rejected and this may be due to the \
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

pub async fn submit_ibc_transfer<N: Namada>(
    namada: &N,
    args: args::TxIbcTransfer,
) -> Result<(), error::Error>
where
    <N::Client as namada::ledger::queries::Client>::Error: std::fmt::Display,
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
    <N::Client as namada::ledger::queries::Client>::Error: std::fmt::Display,
{
    let current_epoch = rpc::query_and_print_epoch(namada).await;
    let governance_parameters =
        rpc::query_governance_parameters(namada.client()).await;
    let (mut tx_builder, signing_data) = if args.is_offline {
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

        let mut wallet = namada.wallet_mut().await;
        let signed_offline_proposal = proposal.sign(
            args.tx
                .signing_keys
                .iter()
                .map(|pk| wallet.find_key_by_pk(pk, None))
                .collect::<Result<_, _>>()
                .expect("secret keys corresponding to public keys not found"),
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
    <N::Client as namada::ledger::queries::Client>::Error: std::fmt::Display,
{
    let (mut tx_builder, signing_data) = if args.is_offline {
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

        let mut wallet = namada.wallet_mut().await;
        let offline_signed_vote = offline_vote.sign(
            args.tx
                .signing_keys
                .iter()
                .map(|pk| wallet.find_key_by_pk(pk, None))
                .collect::<Result<_, _>>()
                .expect("secret keys corresponding to public keys not found"),
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

pub async fn submit_reveal_pk<N: Namada>(
    namada: &N,
    args: args::RevealPk,
) -> Result<(), error::Error>
where
    <N::Client as namada::ledger::queries::Client>::Error: std::fmt::Display,
{
    submit_reveal_aux(namada, args.tx, &(&args.public_key).into()).await?;

    Ok(())
}

pub async fn submit_bond<N: Namada>(
    namada: &N,
    args: args::Bond,
) -> Result<(), error::Error>
where
    <N::Client as namada::ledger::queries::Client>::Error: std::fmt::Display,
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
    <N::Client as namada::ledger::queries::Client>::Error: std::fmt::Display,
{
    let (mut tx, signing_data, latest_withdrawal_pre) =
        args.build(namada).await?;

    if args.tx.dump_tx {
        tx::dump_tx(namada.io(), &args.tx, tx);
    } else {
        sign(namada, &mut tx, &args.tx, signing_data).await?;
        let resp = namada.submit(tx, &args.tx).await?;

        if !args.tx.dry_run && resp.is_applied_and_valid().is_some() {
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
    <N::Client as namada::ledger::queries::Client>::Error: std::fmt::Display,
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
    <N::Client as namada::ledger::queries::Client>::Error: std::fmt::Display,
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
    <N::Client as namada::ledger::queries::Client>::Error: std::fmt::Display,
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
    <N::Client as namada::ledger::queries::Client>::Error: std::fmt::Display,
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
    <N::Client as namada::ledger::queries::Client>::Error: std::fmt::Display,
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
    <N::Client as namada::ledger::queries::Client>::Error: std::fmt::Display,
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
    <N::Client as namada::ledger::queries::Client>::Error: std::fmt::Display,
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
    <N::Client as namada::ledger::queries::Client>::Error: std::fmt::Display,
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
    <N::Client as namada::ledger::queries::Client>::Error: std::fmt::Display,
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
    <N::Client as namada::ledger::queries::Client>::Error: std::fmt::Display,
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

pub async fn gen_ibc_shielded_transfer(
    context: &impl Namada,
    args: args::GenIbcShieldedTransafer,
) -> Result<(), error::Error> {
    if let Some(shielded_transfer) =
        tx::gen_ibc_shielded_transfer(context, args.clone()).await?
    {
        let tx_id = shielded_transfer.masp_tx.txid().to_string();
        let filename = format!("ibc_shielded_transfer_{}.memo", tx_id);
        let output_path = match &args.output_folder {
            Some(path) => path.join(filename),
            None => filename.into(),
        };
        let mut out = File::create(&output_path)
            .expect("Should be able to create the out file.");
        out.write_all(Memo::from(shielded_transfer).as_ref().as_bytes())
            .expect("IBC memo should be deserializable.");
        println!(
            "Output IBC shielded transfer for {tx_id} to {}",
            output_path.to_string_lossy()
        );
    } else {
        eprintln!("No shielded transfer for this IBC transfer.")
    }
    Ok(())
}
