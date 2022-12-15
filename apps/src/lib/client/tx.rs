use std::borrow::Cow;
use std::collections::HashSet;
use std::env;
use std::fmt::Debug;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::PathBuf;

use async_std::io::prelude::WriteExt;
use async_std::io::{self};
use borsh::{BorshDeserialize, BorshSerialize};
use itertools::Either::*;
use masp_primitives::asset_type::AssetType;
use masp_primitives::merkle_tree::MerklePath;
use masp_primitives::sapling::Node;
use masp_primitives::transaction::builder;
use masp_proofs::prover::LocalTxProver;
use namada::ibc::applications::ics20_fungible_token_transfer::msgs::transfer::MsgTransfer;
use namada::ibc::signer::Signer;
use namada::ibc::timestamp::Timestamp as IbcTimestamp;
use namada::ibc::tx_msg::Msg;
use namada::ibc::Height as IbcHeight;
use namada::ibc_proto::cosmos::base::v1beta1::Coin;
use namada::ledger::governance::storage as gov_storage;
use namada::ledger::masp;
use namada::ledger::masp::ShieldedContext;
use namada::ledger::pos::{BondId, Bonds, CommissionRates, Unbonds};
use namada::proto::Tx;
use namada::types::address::{masp, masp_tx_key, Address};
use namada::types::governance::{
    OfflineProposal, OfflineVote, Proposal, ProposalVote,
};
use namada::types::key::*;
use namada::types::masp::TransferTarget;
use namada::types::storage::{
    Epoch, BlockResults, RESERVED_ADDRESS_PREFIX,
};
use namada::types::time::DateTimeUtc;
use namada::types::transaction::governance::{
    InitProposalData, VoteProposalData,
};
use namada::types::transaction::{pos, InitAccount, InitValidator, UpdateVp};
use namada::types::{storage, token};
use namada::{ledger, vm};
use namada::ledger::masp::ShieldedUtils;
use rust_decimal::Decimal;
use tokio::time::{Duration, Instant};
use async_trait::async_trait;

use super::rpc;
use crate::cli::context::WalletAddress;
use crate::cli::{args, safe_exit, Context};
use crate::client::rpc::{query_conversion, query_storage_value};
use crate::client::signing::{find_keypair, sign_tx, tx_signer, TxSigningKey};
use crate::client::tendermint_rpc_types::{TxBroadcastData, TxResponse};
use crate::facade::tendermint_config::net::Address as TendermintAddress;
use crate::facade::tendermint_rpc::endpoint::broadcast::tx_sync::Response;
use crate::facade::tendermint_rpc::error::Error as RpcError;
use crate::facade::tendermint_rpc::{Client, HttpClient};
use crate::node::ledger::tendermint_node;
use crate::wallet::Wallet;

/// Timeout for requests to the `/accepted` and `/applied`
/// ABCI query endpoints.
const ENV_VAR_NAMADA_EVENTS_MAX_WAIT_TIME_SECONDS: &str =
    "ANOMA_EVENTS_MAX_WAIT_TIME_SECONDS";

/// Default timeout in seconds for requests to the `/accepted`
/// and `/applied` ABCI query endpoints.
const DEFAULT_NAMADA_EVENTS_MAX_WAIT_TIME_SECONDS: u64 = 60;

pub async fn submit_custom(client: &HttpClient, wallet: &mut Wallet, args: args::TxCustom) {
    let tx_code = args.code_path;
    let data = args.data_path;
    let tx = Tx::new(tx_code, data);
    let initialized_accounts =
        process_tx(client, wallet, &args.tx, tx, TxSigningKey::None).await;
    save_initialized_accounts(wallet, &args.tx, initialized_accounts).await;
}

pub async fn submit_update_vp(client: &HttpClient, wallet: &mut Wallet, args: args::TxUpdateVp) {
    let addr = args.addr.clone();

    // Check that the address is established and exists on chain
    match &addr {
        Address::Established(_) => {
            let exists =
                rpc::known_address(client, &addr).await;
            if !exists {
                eprintln!("The address {} doesn't exist on chain.", addr);
                if !args.tx.force {
                    safe_exit(1)
                }
            }
        }
        Address::Implicit(_) => {
            eprintln!(
                "A validity predicate of an implicit address cannot be \
                 directly updated. You can use an established address for \
                 this purpose."
            );
            if !args.tx.force {
                safe_exit(1)
            }
        }
        Address::Internal(_) => {
            eprintln!(
                "A validity predicate of an internal address cannot be \
                 directly updated."
            );
            if !args.tx.force {
                safe_exit(1)
            }
        }
    }

    let vp_code = args.vp_code_path;
    // Validate the VP code
    if let Err(err) = vm::validate_untrusted_wasm(&vp_code) {
        eprintln!("Validity predicate code validation failed with {}", err);
        if !args.tx.force {
            safe_exit(1)
        }
    }

    let tx_code = args.tx_code_path;

    let data = UpdateVp { addr, vp_code };
    let data = data.try_to_vec().expect("Encoding tx data shouldn't fail");

    let tx = Tx::new(tx_code, Some(data));
    process_tx(client, wallet, &args.tx, tx, TxSigningKey::WalletAddress(args.addr)).await;
}

pub async fn submit_init_account(client: &HttpClient, wallet: &mut Wallet, args: args::TxInitAccount) {
    let public_key = args.public_key;
    let vp_code = args.vp_code_path;
    // Validate the VP code
    if let Err(err) = vm::validate_untrusted_wasm(&vp_code) {
        eprintln!("Validity predicate code validation failed with {}", err);
        if !args.tx.force {
            safe_exit(1)
        }
    }

    let tx_code = args.tx_code_path;
    let data = InitAccount {
        public_key,
        vp_code,
    };
    let data = data.try_to_vec().expect("Encoding tx data shouldn't fail");

    let tx = Tx::new(tx_code, Some(data));
    let initialized_accounts =
        process_tx(client, wallet, &args.tx, tx, TxSigningKey::WalletAddress(args.source))
            .await;
    save_initialized_accounts(wallet, &args.tx, initialized_accounts).await;
}

pub async fn submit_init_validator(
    client: &HttpClient,
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
        ctx.wallet.gen_validator_keys(protocol_key, scheme).unwrap();
    let protocol_key = validator_keys.get_protocol_keypair().ref_to();
    let dkg_key = validator_keys
        .dkg_keypair
        .as_ref()
        .expect("DKG sessions keys should have been created")
        .public();

    ctx.wallet.save().unwrap_or_else(|err| eprintln!("{}", err));

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
    let initialized_accounts =
        process_tx(client, &mut ctx.wallet, &tx_args, tx, TxSigningKey::WalletAddress(source))
            .await;
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
        ctx.wallet.save().unwrap_or_else(|err| eprintln!("{}", err));

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
    pub fn new(
        context_dir: PathBuf,
    ) -> masp::ShieldedContext<Self> {
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
        masp::ShieldedContext { utils, ..Default::default() }
    }
}

impl Default for CLIShieldedUtils {
    fn default() -> Self {
        Self { context_dir: PathBuf::from(FILE_NAME) }
    }
}

#[async_trait]
impl masp::ShieldedUtils for CLIShieldedUtils {
    type C = HttpClient;
    
    async fn query_storage_value<T: Send>(
        client: &HttpClient,
        key: &storage::Key,
    ) -> Option<T>
    where T: BorshDeserialize {
        query_storage_value::<T>(client, &key).await
    }

    async fn query_epoch(client: &HttpClient) -> Epoch {
        rpc::query_epoch(client).await
    }

    fn local_tx_prover(&self) -> LocalTxProver {
        if let Ok(params_dir) = env::var(masp::ENV_VAR_MASP_PARAMS_DIR)
        {
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

    /// Query a conversion.
    async fn query_conversion(
        client: &HttpClient,
        asset_type: AssetType,
    ) -> Option<(
        Address,
        Epoch,
        masp_primitives::transaction::components::Amount,
        MerklePath<Node>,
    )> {
        query_conversion(client.clone(), asset_type).await
    }

    async fn query_results(client: &HttpClient) -> Vec<BlockResults> {
        rpc::query_results(client).await
    }
}



pub async fn submit_transfer<U: ShieldedUtils<C = HttpClient>>(
    client: &HttpClient,
    wallet: &mut Wallet,
    shielded: &mut ShieldedContext<U>,
    args: args::TxTransfer,
) {
    let transfer_source = args.source;
    let source = transfer_source.effective_address();
    let transfer_target = args.target.clone();
    let target = transfer_target.effective_address();
    // Check that the source address exists on chain
    let source_exists =
        rpc::known_address(client, &source).await;
    if !source_exists {
        eprintln!("The source address {} doesn't exist on chain.", source);
        if !args.tx.force {
            safe_exit(1)
        }
    }
    // Check that the target address exists on chain
    let target_exists =
        rpc::known_address(client, &target).await;
    if !target_exists {
        eprintln!("The target address {} doesn't exist on chain.", target);
        if !args.tx.force {
            safe_exit(1)
        }
    }
    let token = &args.token;
    // Check that the token address exists on chain
    let token_exists =
        rpc::known_address(client, &token)
            .await;
    if !token_exists {
        eprintln!(
            "The token address {} doesn't exist on chain.",
            token
        );
        if !args.tx.force {
            safe_exit(1)
        }
    }
    // Check source balance
    let (sub_prefix, balance_key) = match &args.sub_prefix {
        Some(sub_prefix) => {
            let sub_prefix = storage::Key::parse(sub_prefix).unwrap();
            let prefix = token::multitoken_balance_prefix(
                &token,
                &sub_prefix,
            );
            (
                Some(sub_prefix),
                token::multitoken_balance_key(&prefix, &source),
            )
        }
        None => (None, token::balance_key(&token, &source)),
    };
    match rpc::query_storage_value::<token::Amount>(&client, &balance_key).await
    {
        Some(balance) => {
            if balance < args.amount {
                eprintln!(
                    "The balance of the source {} of token {} is lower than \
                     the amount to be transferred. Amount to transfer is {} \
                     and the balance is {}.",
                    source, token, args.amount, balance
                );
                if !args.tx.force {
                    safe_exit(1)
                }
            }
        }
        None => {
            eprintln!(
                "No balance found for the source {} of token {}",
                source, token
            );
            if !args.tx.force {
                safe_exit(1)
            }
        }
    };

    let tx_code = args.tx_code_path;
    let masp_addr = masp();
    // For MASP sources, use a special sentinel key recognized by VPs as default
    // signer. Also, if the transaction is shielded, redact the amount and token
    // types by setting the transparent value to 0 and token type to a constant.
    // This has no side-effect because transaction is to self.
    let (default_signer, amount, token) =
        if source == masp_addr && target == masp_addr {
            // TODO Refactor me, we shouldn't rely on any specific token here.
            (
                TxSigningKey::SecretKey(masp_tx_key()),
                0.into(),
                args.native_token.clone(),
            )
        } else if source == masp_addr {
            (
                TxSigningKey::SecretKey(masp_tx_key()),
                args.amount,
                token.clone(),
            )
        } else {
            (
                TxSigningKey::WalletAddress(source.clone()),
                args.amount,
                token.clone(),
            )
        };
    // If our chosen signer is the MASP sentinel key, then our shielded inputs
    // will need to cover the gas fees.
    let chosen_signer = tx_signer(client, wallet, &args.tx, default_signer.clone())
        .await
        .ref_to();
    let shielded_gas = masp_tx_key().ref_to() == chosen_signer;
    // Determine whether to pin this transaction to a storage key
    let key = match &args.target {
        TransferTarget::PaymentAddress(pa) if pa.is_pinned() => Some(pa.hash()),
        _ => None,
    };

    let stx_result =
        shielded.gen_shielded_transfer(
            client,
            transfer_source,
            transfer_target,
            args.amount,
            args.token,
            args.tx.fee_amount,
            args.tx.fee_token.clone(),
            shielded_gas,
        )
        .await;
    let shielded = match stx_result {
        Ok(stx) => stx.map(|x| x.0),
        Err(builder::Error::ChangeIsNegative(_)) => {
            eprintln!(
                "The balance of the source {} is lower than the \
                 amount to be transferred and fees. Amount to \
                 transfer is {} {} and fees are {} {}.",
                source,
                args.amount,
                token,
                args.tx.fee_amount,
                &args.tx.fee_token,
            );
            safe_exit(1)
        }
        Err(err) => panic!("{}", err),
    };

    let transfer = token::Transfer {
        source: source.clone(),
        target,
        token,
        sub_prefix,
        amount,
        key,
        shielded,
    };
    tracing::debug!("Transfer data {:?}", transfer);
    let data = transfer
        .try_to_vec()
        .expect("Encoding tx data shouldn't fail");

    let tx = Tx::new(tx_code, Some(data));
    let signing_address = TxSigningKey::WalletAddress(source);
    process_tx(client, wallet, &args.tx, tx, signing_address).await;
}

pub async fn submit_ibc_transfer(client: &HttpClient, wallet: &mut Wallet, args: args::TxIbcTransfer) {
    let source = args.source.clone();
    // Check that the source address exists on chain
    let source_exists =
        rpc::known_address(client, &source).await;
    if !source_exists {
        eprintln!("The source address {} doesn't exist on chain.", source);
        if !args.tx.force {
            safe_exit(1)
        }
    }

    // We cannot check the receiver

    let token = args.token;
    // Check that the token address exists on chain
    let token_exists =
        rpc::known_address(client, &token).await;
    if !token_exists {
        eprintln!("The token address {} doesn't exist on chain.", token);
        if !args.tx.force {
            safe_exit(1)
        }
    }
    // Check source balance
    let (sub_prefix, balance_key) = match args.sub_prefix {
        Some(sub_prefix) => {
            let sub_prefix = storage::Key::parse(sub_prefix).unwrap();
            let prefix = token::multitoken_balance_prefix(&token, &sub_prefix);
            (
                Some(sub_prefix),
                token::multitoken_balance_key(&prefix, &source),
            )
        }
        None => (None, token::balance_key(&token, &source)),
    };
    match rpc::query_storage_value::<token::Amount>(&client, &balance_key).await
    {
        Some(balance) => {
            if balance < args.amount {
                eprintln!(
                    "The balance of the source {} of token {} is lower than \
                     the amount to be transferred. Amount to transfer is {} \
                     and the balance is {}.",
                    source, token, args.amount, balance
                );
                if !args.tx.force {
                    safe_exit(1)
                }
            }
        }
        None => {
            eprintln!(
                "No balance found for the source {} of token {}",
                source, token
            );
            if !args.tx.force {
                safe_exit(1)
            }
        }
    }
    let tx_code = args.tx_code_path;

    let denom = match sub_prefix {
        // To parse IbcToken address, remove the address prefix
        Some(sp) => sp.to_string().replace(RESERVED_ADDRESS_PREFIX, ""),
        None => token.to_string(),
    };
    let token = Some(Coin {
        denom,
        amount: args.amount.to_string(),
    });

    // this height should be that of the destination chain, not this chain
    let timeout_height = match args.timeout_height {
        Some(h) => IbcHeight::new(0, h),
        None => IbcHeight::zero(),
    };

    let now: namada::tendermint::Time = DateTimeUtc::now().try_into().unwrap();
    let now: IbcTimestamp = now.into();
    let timeout_timestamp = if let Some(offset) = args.timeout_sec_offset {
        (now + Duration::new(offset, 0)).unwrap()
    } else if timeout_height.is_zero() {
        // we cannot set 0 to both the height and the timestamp
        (now + Duration::new(3600, 0)).unwrap()
    } else {
        IbcTimestamp::none()
    };

    let msg = MsgTransfer {
        source_port: args.port_id,
        source_channel: args.channel_id,
        token,
        sender: Signer::new(source.to_string()),
        receiver: Signer::new(args.receiver),
        timeout_height,
        timeout_timestamp,
    };
    tracing::debug!("IBC transfer message {:?}", msg);
    let any_msg = msg.to_any();
    let mut data = vec![];
    prost::Message::encode(&any_msg, &mut data)
        .expect("Encoding tx data shouldn't fail");

    let tx = Tx::new(tx_code, Some(data));
    process_tx(client, wallet, &args.tx, tx, TxSigningKey::WalletAddress(args.source))
        .await;
}

pub async fn submit_init_proposal(client: &HttpClient, mut ctx: Context, args: args::InitProposal) {
    let file = File::open(&args.proposal_data).expect("File must exist.");
    let proposal: Proposal =
        serde_json::from_reader(file).expect("JSON was not well-formatted");

    let signer = WalletAddress::new(proposal.clone().author.to_string());
    let governance_parameters = rpc::get_governance_parameters(&client).await;
    let current_epoch = rpc::query_epoch(client)
    .await;

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
        let signing_key = find_keypair(
            client,
            &mut ctx.wallet,
            &signer,
        )
        .await;
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
            &client,
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

        process_tx(client, &mut ctx.wallet, &args.tx, tx, TxSigningKey::WalletAddress(signer))
            .await;
    }
}

pub async fn submit_vote_proposal(client: &HttpClient, wallet: &mut Wallet, args: args::VoteProposal) {
    let signer = if let Some(addr) = &args.tx.signer {
        addr
    } else {
        eprintln!("Missing mandatory argument --signer.");
        safe_exit(1)
    };

    if args.offline {
        let signer = signer;
        let proposal_file_path =
            args.proposal_data.expect("Proposal file should exist.");
        let file = File::open(&proposal_file_path).expect("File must exist.");

        let proposal: OfflineProposal =
            serde_json::from_reader(file).expect("JSON was not well-formatted");
        let public_key = rpc::get_public_key(
            client,
            &proposal.address,
        )
        .await
        .expect("Public key should exist.");
        if !proposal.check_signature(&public_key) {
            eprintln!("Proposal signature mismatch!");
            safe_exit(1)
        }

        let signing_key = find_keypair(
            client,
            wallet,
            &signer,
        )
        .await;
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
            }
            Err(e) => {
                eprintln!("Error while creating proposal vote file: {}.", e);
                safe_exit(1)
            }
        }
    } else {
        let current_epoch = rpc::query_epoch(client)
        .await;

        let voter_address = signer.clone();
        let proposal_id = args.proposal_id.unwrap();
        let proposal_start_epoch_key =
            gov_storage::get_voting_start_epoch_key(proposal_id);
        let proposal_start_epoch = rpc::query_storage_value::<Epoch>(
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
                    rpc::get_delegators_delegation(&client, &voter_address)
                        .await;

                // Optimize by quering if a vote from a validator
                // is equal to ours. If so, we can avoid voting, but ONLY if we
                // are  voting in the last third of the voting
                // window, otherwise there's  the risk of the
                // validator changing his vote and, effectively, invalidating
                // the delgator's vote
                if !args.tx.force
                    && is_safe_voting_window(
                        client,
                        proposal_id,
                        epoch,
                    )
                    .await
                {
                    delegations = filter_delegations(
                        &client,
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

                process_tx(
                    client,
                    wallet,
                    &args.tx,
                    tx,
                    TxSigningKey::WalletAddress(signer.clone()),
                )
                .await;
            }
            None => {
                eprintln!(
                    "Proposal start epoch for proposal id {} is not definied.",
                    proposal_id
                );
                if !args.tx.force {
                    safe_exit(1)
                }
            }
        }
    }
}

pub async fn submit_reveal_pk(client: &HttpClient, wallet: &mut Wallet, args: args::RevealPk) {
    let args::RevealPk {
        tx: args,
        public_key,
    } = args;
    let public_key = public_key;
    if !reveal_pk_if_needed(client, wallet, &public_key, &args).await {
        let addr: Address = (&public_key).into();
        println!("PK for {addr} is already revealed, nothing to do.");
    }
}

pub async fn reveal_pk_if_needed(
    client: &HttpClient,
    wallet: &mut Wallet,
    public_key: &common::PublicKey,
    args: &args::Tx,
) -> bool {
    let addr: Address = public_key.into();
    // Check if PK revealed
    if args.force || !has_revealed_pk(client, &addr).await
    {
        // If not, submit it
        submit_reveal_pk_aux(client, wallet, public_key, args).await;
        true
    } else {
        false
    }
}

pub async fn has_revealed_pk(
    client: &HttpClient,
    addr: &Address,
) -> bool {
    rpc::get_public_key(client, addr).await.is_some()
}

pub async fn submit_reveal_pk_aux(
    client: &HttpClient,
    wallet: &mut Wallet,
    public_key: &common::PublicKey,
    args: &args::Tx,
) {
    let addr: Address = public_key.into();
    println!("Submitting a tx to reveal the public key for address {addr}...");
    let tx_data = public_key
        .try_to_vec()
        .expect("Encoding a public key shouldn't fail");
    let tx_code = args.tx_code_path.clone();
    let tx = Tx::new(tx_code, Some(tx_data));

    // submit_tx without signing the inner tx
    let keypair = if let Some(signing_key) = &args.signing_key {
        signing_key.clone()
    } else if let Some(signer) = args.signer.as_ref() {
        let signer = signer;
        find_keypair(client, wallet, &signer)
            .await
    } else {
        find_keypair(client, wallet, &addr).await
    };
    let epoch = rpc::query_epoch(client)
    .await;
    let to_broadcast = if args.dry_run {
        TxBroadcastData::DryRun(tx)
    } else {
        super::signing::sign_wrapper(args, epoch, tx, &keypair).await
    };

    if args.dry_run {
        if let TxBroadcastData::DryRun(tx) = to_broadcast {
            rpc::dry_run_tx(client, tx.to_bytes()).await;
        } else {
            panic!(
                "Expected a dry-run transaction, received a wrapper \
                 transaction instead"
            );
        }
    } else {
        // Either broadcast or submit transaction and collect result into
        // sum type
        let result = if args.broadcast_only {
            Left(broadcast_tx(client, &to_broadcast).await)
        } else {
            Right(submit_tx(client, to_broadcast).await)
        };
        // Return result based on executed operation, otherwise deal with
        // the encountered errors uniformly
        match result {
            Right(Err(err)) => {
                eprintln!(
                    "Encountered error while broadcasting transaction: {}",
                    err
                );
                safe_exit(1)
            }
            Left(Err(err)) => {
                eprintln!(
                    "Encountered error while broadcasting transaction: {}",
                    err
                );
                safe_exit(1)
            }
            _ => {}
        }
    }
}

/// Check if current epoch is in the last third of the voting period of the
/// proposal. This ensures that it is safe to optimize the vote writing to
/// storage.
async fn is_safe_voting_window(
    client: &HttpClient,
    proposal_id: u64,
    proposal_start_epoch: Epoch,
) -> bool {
    let current_epoch = rpc::query_epoch(client).await;

    let proposal_end_epoch_key =
        gov_storage::get_voting_end_epoch_key(proposal_id);
    let proposal_end_epoch =
        rpc::query_storage_value::<Epoch>(client, &proposal_end_epoch_key)
            .await;

    match proposal_end_epoch {
        Some(proposal_end_epoch) => {
            !namada::ledger::native_vp::governance::utils::is_valid_validator_voting_period(
                current_epoch,
                proposal_start_epoch,
                proposal_end_epoch,
            )
        }
        None => {
            eprintln!("Proposal end epoch is not in the storage.");
            safe_exit(1)
        }
    }
}

/// Removes validators whose vote corresponds to that of the delegator (needless
/// vote)
async fn filter_delegations(
    client: &HttpClient,
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
                    rpc::query_storage_value::<ProposalVote>(client, &vote_key)
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

pub async fn submit_bond(client: &HttpClient, wallet: &mut Wallet, args: args::Bond) {
    let validator = args.validator.clone();
    // Check that the validator address exists on chain
    let is_validator =
        rpc::is_validator(client, &validator).await;
    if !is_validator {
        eprintln!(
            "The address {} doesn't belong to any known validator account.",
            validator
        );
        if !args.tx.force {
            safe_exit(1)
        }
    }
    let source = args.source.clone();
    // Check that the source address exists on chain
    if let Some(source) = &source {
        let source_exists =
            rpc::known_address(client, source).await;
        if !source_exists {
            eprintln!("The source address {} doesn't exist on chain.", source);
            if !args.tx.force {
                safe_exit(1)
            }
        }
    }
    // Check bond's source (source for delegation or validator for self-bonds)
    // balance
    let bond_source = source.as_ref().unwrap_or(&validator);
    let balance_key = token::balance_key(&args.native_token, bond_source);
    match rpc::query_storage_value::<token::Amount>(&client, &balance_key).await
    {
        Some(balance) => {
            if balance < args.amount {
                eprintln!(
                    "The balance of the source {} is lower than the amount to \
                     be transferred. Amount to transfer is {} and the balance \
                     is {}.",
                    bond_source, args.amount, balance
                );
                if !args.tx.force {
                    safe_exit(1)
                }
            }
        }
        None => {
            eprintln!("No balance found for the source {}", bond_source);
            if !args.tx.force {
                safe_exit(1)
            }
        }
    }
    let tx_code = args.tx_code_path;
    let bond = pos::Bond {
        validator,
        amount: args.amount,
        source,
    };
    let data = bond.try_to_vec().expect("Encoding tx data shouldn't fail");

    let tx = Tx::new(tx_code, Some(data));
    let default_signer = args.source.unwrap_or(args.validator);
    process_tx(
        client,
        wallet,
        &args.tx,
        tx,
        TxSigningKey::WalletAddress(default_signer),
    )
    .await;
}

pub async fn submit_unbond(client: &HttpClient, wallet: &mut Wallet, args: args::Unbond) {
    let validator = args.validator.clone();
    // Check that the validator address exists on chain
    let is_validator =
        rpc::is_validator(client, &validator).await;
    if !is_validator {
        eprintln!(
            "The address {} doesn't belong to any known validator account.",
            validator
        );
        if !args.tx.force {
            safe_exit(1)
        }
    }

    let source = args.source.clone();
    let tx_code = args.tx_code_path;

    // Check the source's current bond amount
    let bond_source = source.clone().unwrap_or_else(|| validator.clone());
    let bond_id = BondId {
        source: bond_source.clone(),
        validator: validator.clone(),
    };
    let bond_key = ledger::pos::bond_key(&bond_id);
    let bonds = rpc::query_storage_value::<Bonds>(&client, &bond_key).await;
    match bonds {
        Some(bonds) => {
            let mut bond_amount: token::Amount = 0.into();
            for bond in bonds.iter() {
                for delta in bond.pos_deltas.values() {
                    bond_amount += *delta;
                }
            }
            if args.amount > bond_amount {
                eprintln!(
                    "The total bonds of the source {} is lower than the \
                     amount to be unbonded. Amount to unbond is {} and the \
                     total bonds is {}.",
                    bond_source, args.amount, bond_amount
                );
                if !args.tx.force {
                    safe_exit(1)
                }
            }
        }
        None => {
            eprintln!("No bonds found");
            if !args.tx.force {
                safe_exit(1)
            }
        }
    }

    let data = pos::Unbond {
        validator,
        amount: args.amount,
        source,
    };
    let data = data.try_to_vec().expect("Encoding tx data shouldn't fail");

    let tx = Tx::new(tx_code, Some(data));
    let default_signer = args.source.unwrap_or(args.validator);
    process_tx(
        client,
        wallet,
        &args.tx,
        tx,
        TxSigningKey::WalletAddress(default_signer),
    )
    .await;
}

pub async fn submit_withdraw(client: &HttpClient, wallet: &mut Wallet, args: args::Withdraw) {
    let epoch = rpc::query_epoch(client)
    .await;

    let validator = args.validator.clone();
    // Check that the validator address exists on chain
    let is_validator =
        rpc::is_validator(client, &validator).await;
    if !is_validator {
        eprintln!(
            "The address {} doesn't belong to any known validator account.",
            validator
        );
        if !args.tx.force {
            safe_exit(1)
        }
    }

    let source = args.source.clone();
    let tx_code = args.tx_code_path;

    // Check the source's current unbond amount
    let bond_source = source.clone().unwrap_or_else(|| validator.clone());
    let bond_id = BondId {
        source: bond_source.clone(),
        validator: validator.clone(),
    };
    let bond_key = ledger::pos::unbond_key(&bond_id);
    let unbonds = rpc::query_storage_value::<Unbonds>(&client, &bond_key).await;
    match unbonds {
        Some(unbonds) => {
            let mut unbonded_amount: token::Amount = 0.into();
            if let Some(unbond) = unbonds.get(epoch) {
                for delta in unbond.deltas.values() {
                    unbonded_amount += *delta;
                }
            }
            if unbonded_amount == 0.into() {
                eprintln!(
                    "There are no unbonded bonds ready to withdraw in the \
                     current epoch {}.",
                    epoch
                );
                if !args.tx.force {
                    safe_exit(1)
                }
            }
        }
        None => {
            eprintln!("No unbonded bonds found");
            if !args.tx.force {
                safe_exit(1)
            }
        }
    }

    let data = pos::Withdraw { validator, source };
    let data = data.try_to_vec().expect("Encoding tx data shouldn't fail");

    let tx = Tx::new(tx_code, Some(data));
    let default_signer = args.source.unwrap_or(args.validator);
    process_tx(
        client,
        wallet,
        &args.tx,
        tx,
        TxSigningKey::WalletAddress(default_signer),
    )
    .await;
}

pub async fn submit_validator_commission_change(
    client: &HttpClient,
    wallet: &mut Wallet,
    args: args::TxCommissionRateChange,
) {
    let epoch = rpc::query_epoch(client)
    .await;

    let tx_code = args.tx_code_path;

    let validator = args.validator.clone();
    if rpc::is_validator(client, &validator).await {
        if args.rate < Decimal::ZERO || args.rate > Decimal::ONE {
            eprintln!("Invalid new commission rate, received {}", args.rate);
            if !args.tx.force {
                safe_exit(1)
            }
        }

        let commission_rate_key =
            ledger::pos::validator_commission_rate_key(&validator);
        let max_commission_rate_change_key =
            ledger::pos::validator_max_commission_rate_change_key(&validator);
        let commission_rates = rpc::query_storage_value::<CommissionRates>(
            &client,
            &commission_rate_key,
        )
        .await;
        let max_change = rpc::query_storage_value::<Decimal>(
            &client,
            &max_commission_rate_change_key,
        )
        .await;

        match (commission_rates, max_change) {
            (Some(rates), Some(max_change)) => {
                // Assuming that pipeline length = 2
                let rate_next_epoch = rates.get(epoch.next()).unwrap();
                if (args.rate - rate_next_epoch).abs() > max_change {
                    eprintln!(
                        "New rate is too large of a change with respect to \
                         the predecessor epoch in which the rate will take \
                         effect."
                    );
                    if !args.tx.force {
                        safe_exit(1)
                    }
                }
            }
            _ => {
                eprintln!("Error retrieving from storage");
                if !args.tx.force {
                    safe_exit(1)
                }
            }
        }
    } else {
        eprintln!("The given address {validator} is not a validator.");
        if !args.tx.force {
            safe_exit(1)
        }
    }

    let data = pos::CommissionChange {
        validator: args.validator.clone(),
        new_rate: args.rate,
    };
    let data = data.try_to_vec().expect("Encoding tx data shouldn't fail");

    let tx = Tx::new(tx_code, Some(data));
    let default_signer = args.validator.clone();
    process_tx(
        client,
        wallet,
        &args.tx,
        tx,
        TxSigningKey::WalletAddress(default_signer),
    )
    .await;
}

/// Submit transaction and wait for result. Returns a list of addresses
/// initialized in the transaction if any. In dry run, this is always empty.
async fn process_tx(
    client: &HttpClient,
    wallet: &mut Wallet,
    args: &args::Tx,
    tx: Tx,
    default_signer: TxSigningKey,
) -> Vec<Address> {
    let to_broadcast = sign_tx(client, wallet, tx, args, default_signer).await;
    // NOTE: use this to print the request JSON body:

    // let request =
    // tendermint_rpc::endpoint::broadcast::tx_commit::Request::new(
    //     tx_bytes.clone().into(),
    // );
    // use tendermint_rpc::Request;
    // let request_body = request.into_json();
    // println!("HTTP request body: {}", request_body);

    if args.dry_run {
        if let TxBroadcastData::DryRun(tx) = to_broadcast {
            rpc::dry_run_tx(client, tx.to_bytes()).await;
            vec![]
        } else {
            panic!(
                "Expected a dry-run transaction, received a wrapper \
                 transaction instead"
            );
        }
    } else {
        // Either broadcast or submit transaction and collect result into
        // sum type
        let result = if args.broadcast_only {
            Left(broadcast_tx(client, &to_broadcast).await)
        } else {
            Right(submit_tx(client, to_broadcast).await)
        };
        // Return result based on executed operation, otherwise deal with
        // the encountered errors uniformly
        match result {
            Right(Ok(result)) => result.initialized_accounts,
            Left(Ok(_)) => Vec::default(),
            Right(Err(err)) => {
                eprintln!(
                    "Encountered error while broadcasting transaction: {}",
                    err
                );
                safe_exit(1)
            }
            Left(Err(err)) => {
                eprintln!(
                    "Encountered error while broadcasting transaction: {}",
                    err
                );
                safe_exit(1)
            }
        }
    }
}

/// Save accounts initialized from a tx into the wallet, if any.
async fn save_initialized_accounts(
    wallet: &mut Wallet,
    args: &args::Tx,
    initialized_accounts: Vec<Address>,
) {
    let len = initialized_accounts.len();
    if len != 0 {
        // Store newly initialized account addresses in the wallet
        println!(
            "The transaction initialized {} new account{}",
            len,
            if len == 1 { "" } else { "s" }
        );
        // Store newly initialized account addresses in the wallet
        for (ix, address) in initialized_accounts.iter().enumerate() {
            let encoded = address.encode();
            let alias: Cow<str> = match &args.initialized_account_alias {
                Some(initialized_account_alias) => {
                    if len == 1 {
                        // If there's only one account, use the
                        // alias as is
                        initialized_account_alias.into()
                    } else {
                        // If there're multiple accounts, use
                        // the alias as prefix, followed by
                        // index number
                        format!("{}{}", initialized_account_alias, ix).into()
                    }
                }
                None => {
                    print!("Choose an alias for {}: ", encoded);
                    io::stdout().flush().await.unwrap();
                    let mut alias = String::new();
                    io::stdin().read_line(&mut alias).await.unwrap();
                    alias.trim().to_owned().into()
                }
            };
            let alias = alias.into_owned();
            let added = wallet.add_address(alias.clone(), address.clone());
            match added {
                Some(new_alias) if new_alias != encoded => {
                    println!(
                        "Added alias {} for address {}.",
                        new_alias, encoded
                    );
                }
                _ => println!("No alias added for address {}.", encoded),
            };
        }
        if !args.dry_run {
            wallet.save().unwrap_or_else(|err| eprintln!("{}", err));
        } else {
            println!("Transaction dry run. No addresses have been saved.")
        }
    }
}

/// Broadcast a transaction to be included in the blockchain and checks that
/// the tx has been successfully included into the mempool of a validator
///
/// In the case of errors in any of those stages, an error message is returned
pub async fn broadcast_tx(
    rpc_cli: &HttpClient,
    to_broadcast: &TxBroadcastData,
) -> Result<Response, RpcError> {
    let (tx, wrapper_tx_hash, decrypted_tx_hash) = match to_broadcast {
        TxBroadcastData::Wrapper {
            tx,
            wrapper_hash,
            decrypted_hash,
        } => (tx, wrapper_hash, decrypted_hash),
        _ => panic!("Cannot broadcast a dry-run transaction"),
    };

    tracing::debug!(
        transaction = ?to_broadcast,
        "Broadcasting transaction",
    );

    // TODO: configure an explicit timeout value? we need to hack away at
    // `tendermint-rs` for this, which is currently using a hard-coded 30s
    // timeout.
    let response = rpc_cli.broadcast_tx_sync(tx.to_bytes().into()).await?;

    if response.code == 0.into() {
        println!("Transaction added to mempool: {:?}", response);
        // Print the transaction identifiers to enable the extraction of
        // acceptance/application results later
        {
            println!("Wrapper transaction hash: {:?}", wrapper_tx_hash);
            println!("Inner transaction hash: {:?}", decrypted_tx_hash);
        }
        Ok(response)
    } else {
        Err(RpcError::server(serde_json::to_string(&response).unwrap()))
    }
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
) -> Result<TxResponse, RpcError> {
    let (_, wrapper_hash, decrypted_hash) = match &to_broadcast {
        TxBroadcastData::Wrapper {
            tx,
            wrapper_hash,
            decrypted_hash,
        } => (tx, wrapper_hash, decrypted_hash),
        _ => panic!("Cannot broadcast a dry-run transaction"),
    };

    // Broadcast the supplied transaction
    broadcast_tx(client, &to_broadcast).await?;

    let max_wait_time = Duration::from_secs(
        env::var(ENV_VAR_NAMADA_EVENTS_MAX_WAIT_TIME_SECONDS)
            .ok()
            .and_then(|val| val.parse().ok())
            .unwrap_or(DEFAULT_NAMADA_EVENTS_MAX_WAIT_TIME_SECONDS),
    );
    let deadline = Instant::now() + max_wait_time;

    tracing::debug!(
        transaction = ?to_broadcast,
        ?deadline,
        "Awaiting transaction approval",
    );

    let parsed = {
        let wrapper_query = rpc::TxEventQuery::Accepted(wrapper_hash.as_str());
        let event =
            rpc::query_tx_status(client, wrapper_query, deadline)
                .await;
        let parsed = TxResponse::from_event(event);

        println!(
            "Transaction accepted with result: {}",
            serde_json::to_string_pretty(&parsed).unwrap()
        );
        // The transaction is now on chain. We wait for it to be decrypted
        // and applied
        if parsed.code == 0.to_string() {
            // We also listen to the event emitted when the encrypted
            // payload makes its way onto the blockchain
            let decrypted_query =
                rpc::TxEventQuery::Applied(decrypted_hash.as_str());
            let event =
                rpc::query_tx_status(client, decrypted_query, deadline).await;
            let parsed = TxResponse::from_event(event);
            println!(
                "Transaction applied with result: {}",
                serde_json::to_string_pretty(&parsed).unwrap()
            );
            Ok(parsed)
        } else {
            Ok(parsed)
        }
    };

    tracing::debug!(
        transaction = ?to_broadcast,
        "Transaction approved",
    );

    parsed
}
