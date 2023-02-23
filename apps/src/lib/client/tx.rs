use std::collections::HashSet;
use std::env;
use std::fmt::Debug;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::PathBuf;

use async_std::io;
use async_std::io::prelude::WriteExt;
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
use crate::node::ledger::tendermint_node;
use crate::wallet::{gen_validator_keys, read_and_confirm_pwd, CliWalletUtils};

<<<<<<< HEAD
pub async fn submit_custom<
    C: namada::ledger::queries::Client + Sync,
    U: WalletUtils,
>(
    client: &C,
    wallet: &mut Wallet<U>,
    args: args::TxCustom,
) -> Result<(), tx::Error> {
    tx::submit_custom::<C, U>(client, wallet, args).await
||||||| f6262aa20
const TX_INIT_ACCOUNT_WASM: &str = "tx_init_account.wasm";
const TX_INIT_VALIDATOR_WASM: &str = "tx_init_validator.wasm";
const TX_INIT_PROPOSAL: &str = "tx_init_proposal.wasm";
const TX_VOTE_PROPOSAL: &str = "tx_vote_proposal.wasm";
const TX_REVEAL_PK: &str = "tx_reveal_pk.wasm";
const TX_UPDATE_VP_WASM: &str = "tx_update_vp.wasm";
const TX_TRANSFER_WASM: &str = "tx_transfer.wasm";
const TX_IBC_WASM: &str = "tx_ibc.wasm";
const VP_USER_WASM: &str = "vp_user.wasm";
const TX_BOND_WASM: &str = "tx_bond.wasm";
const TX_UNBOND_WASM: &str = "tx_unbond.wasm";
const TX_WITHDRAW_WASM: &str = "tx_withdraw.wasm";
const TX_CHANGE_COMMISSION_WASM: &str = "tx_change_validator_commission.wasm";

/// Timeout for requests to the `/accepted` and `/applied`
/// ABCI query endpoints.
const ENV_VAR_NAMADA_EVENTS_MAX_WAIT_TIME_SECONDS: &str =
    "NAMADA_EVENTS_MAX_WAIT_TIME_SECONDS";

/// Default timeout in seconds for requests to the `/accepted`
/// and `/applied` ABCI query endpoints.
const DEFAULT_NAMADA_EVENTS_MAX_WAIT_TIME_SECONDS: u64 = 60;

pub async fn submit_custom(ctx: Context, args: args::TxCustom) {
    let tx_code = ctx.read_wasm(args.code_path);
    let data = args.data_path.map(|data_path| {
        std::fs::read(data_path).expect("Expected a file at given data path")
    });
    let tx = Tx::new(tx_code, data);
    let (ctx, initialized_accounts) =
        process_tx(ctx, &args.tx, tx, TxSigningKey::None).await;
    save_initialized_accounts(ctx, &args.tx, initialized_accounts).await;
=======
const TX_INIT_ACCOUNT_WASM: &str = "tx_init_account.wasm";
const TX_INIT_VALIDATOR_WASM: &str = "tx_init_validator.wasm";
const TX_INIT_PROPOSAL: &str = "tx_init_proposal.wasm";
const TX_VOTE_PROPOSAL: &str = "tx_vote_proposal.wasm";
const TX_REVEAL_PK: &str = "tx_reveal_pk.wasm";
const TX_UPDATE_VP_WASM: &str = "tx_update_vp.wasm";
const TX_TRANSFER_WASM: &str = "tx_transfer.wasm";
const TX_IBC_WASM: &str = "tx_ibc.wasm";
const VP_USER_WASM: &str = "vp_user.wasm";
const TX_BOND_WASM: &str = "tx_bond.wasm";
const TX_UNBOND_WASM: &str = "tx_unbond.wasm";
const TX_WITHDRAW_WASM: &str = "tx_withdraw.wasm";
const TX_CHANGE_COMMISSION_WASM: &str = "tx_change_validator_commission.wasm";

/// Timeout for requests to the `/accepted` and `/applied`
/// ABCI query endpoints.
const ENV_VAR_NAMADA_EVENTS_MAX_WAIT_TIME_SECONDS: &str =
    "NAMADA_EVENTS_MAX_WAIT_TIME_SECONDS";

/// Default timeout in seconds for requests to the `/accepted`
/// and `/applied` ABCI query endpoints.
const DEFAULT_NAMADA_EVENTS_MAX_WAIT_TIME_SECONDS: u64 = 60;

pub async fn submit_custom(ctx: Context, args: args::TxCustom) {
    let tx_code = ctx.read_wasm(args.code_path);
    let data = args.data_path.map(|data_path| {
        std::fs::read(data_path).expect("Expected a file at given data path")
    });
    let tx = Tx::new(tx_code, data);
    let (ctx, initialized_accounts) = process_tx(
        ctx,
        &args.tx,
        tx,
        TxSigningKey::None,
        #[cfg(not(feature = "mainnet"))]
        false,
    )
    .await;
    save_initialized_accounts(ctx, &args.tx, initialized_accounts).await;
>>>>>>> v0.13.0
}

<<<<<<< HEAD
pub async fn submit_update_vp<
    C: namada::ledger::queries::Client + Sync,
    U: WalletUtils,
>(
    client: &C,
    wallet: &mut Wallet<U>,
    args: args::TxUpdateVp,
) -> Result<(), tx::Error> {
    tx::submit_update_vp::<C, U>(client, wallet, args).await
||||||| f6262aa20
pub async fn submit_update_vp(ctx: Context, args: args::TxUpdateVp) {
    let addr = ctx.get(&args.addr);

    // Check that the address is established and exists on chain
    match &addr {
        Address::Established(_) => {
            let exists =
                rpc::known_address(&addr, args.tx.ledger_address.clone()).await;
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

    let vp_code = ctx.read_wasm(args.vp_code_path);
    // Validate the VP code
    if let Err(err) = vm::validate_untrusted_wasm(&vp_code) {
        eprintln!("Validity predicate code validation failed with {}", err);
        if !args.tx.force {
            safe_exit(1)
        }
    }

    let tx_code = ctx.read_wasm(TX_UPDATE_VP_WASM);

    let data = UpdateVp { addr, vp_code };
    let data = data.try_to_vec().expect("Encoding tx data shouldn't fail");

    let tx = Tx::new(tx_code, Some(data));
    process_tx(ctx, &args.tx, tx, TxSigningKey::WalletAddress(args.addr)).await;
=======
pub async fn submit_update_vp(ctx: Context, args: args::TxUpdateVp) {
    let addr = ctx.get(&args.addr);

    // Check that the address is established and exists on chain
    match &addr {
        Address::Established(_) => {
            let exists =
                rpc::known_address(&addr, args.tx.ledger_address.clone()).await;
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

    let vp_code = ctx.read_wasm(args.vp_code_path);
    // Validate the VP code
    if let Err(err) = vm::validate_untrusted_wasm(&vp_code) {
        eprintln!("Validity predicate code validation failed with {}", err);
        if !args.tx.force {
            safe_exit(1)
        }
    }

    let tx_code = ctx.read_wasm(TX_UPDATE_VP_WASM);

    let data = UpdateVp { addr, vp_code };
    let data = data.try_to_vec().expect("Encoding tx data shouldn't fail");

    let tx = Tx::new(tx_code, Some(data));
    process_tx(
        ctx,
        &args.tx,
        tx,
        TxSigningKey::WalletAddress(args.addr),
        #[cfg(not(feature = "mainnet"))]
        false,
    )
    .await;
>>>>>>> v0.13.0
}

<<<<<<< HEAD
pub async fn submit_init_account<
    C: namada::ledger::queries::Client + Sync,
    U: WalletUtils,
>(
    client: &C,
    wallet: &mut Wallet<U>,
    args: args::TxInitAccount,
) -> Result<(), tx::Error> {
    tx::submit_init_account::<C, U>(client, wallet, args).await
||||||| f6262aa20
pub async fn submit_init_account(mut ctx: Context, args: args::TxInitAccount) {
    let public_key = ctx.get_cached(&args.public_key);
    let vp_code = args
        .vp_code_path
        .map(|path| ctx.read_wasm(path))
        .unwrap_or_else(|| ctx.read_wasm(VP_USER_WASM));
    // Validate the VP code
    if let Err(err) = vm::validate_untrusted_wasm(&vp_code) {
        eprintln!("Validity predicate code validation failed with {}", err);
        if !args.tx.force {
            safe_exit(1)
        }
    }

    let tx_code = ctx.read_wasm(TX_INIT_ACCOUNT_WASM);
    let data = InitAccount {
        public_key,
        vp_code,
    };
    let data = data.try_to_vec().expect("Encoding tx data shouldn't fail");

    let tx = Tx::new(tx_code, Some(data));
    let (ctx, initialized_accounts) =
        process_tx(ctx, &args.tx, tx, TxSigningKey::WalletAddress(args.source))
            .await;
    save_initialized_accounts(ctx, &args.tx, initialized_accounts).await;
=======
pub async fn submit_init_account(mut ctx: Context, args: args::TxInitAccount) {
    let public_key = ctx.get_cached(&args.public_key);
    let vp_code = args
        .vp_code_path
        .map(|path| ctx.read_wasm(path))
        .unwrap_or_else(|| ctx.read_wasm(VP_USER_WASM));
    // Validate the VP code
    if let Err(err) = vm::validate_untrusted_wasm(&vp_code) {
        eprintln!("Validity predicate code validation failed with {}", err);
        if !args.tx.force {
            safe_exit(1)
        }
    }

    let tx_code = ctx.read_wasm(TX_INIT_ACCOUNT_WASM);
    let data = InitAccount {
        public_key,
        vp_code,
    };
    let data = data.try_to_vec().expect("Encoding tx data shouldn't fail");

    let tx = Tx::new(tx_code, Some(data));
    let (ctx, initialized_accounts) = process_tx(
        ctx,
        &args.tx,
        tx,
        TxSigningKey::WalletAddress(args.source),
        #[cfg(not(feature = "mainnet"))]
        false,
    )
    .await;
    save_initialized_accounts(ctx, &args.tx, initialized_accounts).await;
>>>>>>> v0.13.0
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
<<<<<<< HEAD
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
||||||| f6262aa20
    let (mut ctx, initialized_accounts) =
        process_tx(ctx, &tx_args, tx, TxSigningKey::WalletAddress(source))
            .await;
=======
    let (mut ctx, initialized_accounts) = process_tx(
        ctx,
        &tx_args,
        tx,
        TxSigningKey::WalletAddress(source),
        #[cfg(not(feature = "mainnet"))]
        false,
    )
    .await;
>>>>>>> v0.13.0
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

<<<<<<< HEAD
impl masp::ShieldedUtils for CLIShieldedUtils {
    type C = tendermint_rpc::HttpClient;

    fn local_tx_prover(&self) -> LocalTxProver {
        if let Ok(params_dir) = env::var(masp::ENV_VAR_MASP_PARAMS_DIR) {
            let params_dir = PathBuf::from(params_dir);
            let spend_path = params_dir.join(masp::SPEND_NAME);
            let convert_path = params_dir.join(masp::CONVERT_NAME);
            let output_path = params_dir.join(masp::OUTPUT_NAME);
            LocalTxProver::new(&spend_path, &output_path, &convert_path)
||||||| f6262aa20
    /// Applies the given transaction to the supplied context. More precisely,
    /// the shielded transaction's outputs are added to the commitment tree.
    /// Newly discovered notes are associated to the supplied viewing keys. Note
    /// nullifiers are mapped to their originating notes. Note positions are
    /// associated to notes, memos, and diversifiers. And the set of notes that
    /// we have spent are updated. The witness map is maintained to make it
    /// easier to construct note merkle paths in other code. See
    /// https://zips.z.cash/protocol/protocol.pdf#scan
    pub fn scan_tx(
        &mut self,
        height: BlockHeight,
        index: TxIndex,
        epoch: Epoch,
        tx: &Transfer,
    ) {
        // Ignore purely transparent transactions
        let shielded = if let Some(shielded) = &tx.shielded {
            shielded
=======
    /// Applies the given transaction to the supplied context. More precisely,
    /// the shielded transaction's outputs are added to the commitment tree.
    /// Newly discovered notes are associated to the supplied viewing keys. Note
    /// nullifiers are mapped to their originating notes. Note positions are
    /// associated to notes, memos, and diversifiers. And the set of notes that
    /// we have spent are updated. The witness map is maintained to make it
    /// easier to construct note merkle paths in other code. See
    /// <https://zips.z.cash/protocol/protocol.pdf#scan>
    pub fn scan_tx(
        &mut self,
        height: BlockHeight,
        index: TxIndex,
        epoch: Epoch,
        tx: &Transfer,
    ) {
        // Ignore purely transparent transactions
        let shielded = if let Some(shielded) = &tx.shielded {
            shielded
>>>>>>> v0.13.0
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
    C: namada::ledger::queries::Client + Sync,
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
    C: namada::ledger::queries::Client + Sync,
    U: WalletUtils,
>(
    client: &C,
    wallet: &mut Wallet<U>,
    args: args::TxIbcTransfer,
) -> Result<(), tx::Error> {
    tx::submit_ibc_transfer::<C, U>(client, wallet, args).await
}

<<<<<<< HEAD
pub async fn submit_init_proposal<C: namada::ledger::queries::Client + Sync>(
    client: &C,
    mut ctx: Context,
    args: args::InitProposal,
) -> Result<(), tx::Error> {
||||||| f6262aa20
/// Make shielded components to embed within a Transfer object. If no shielded
/// payment address nor spending key is specified, then no shielded components
/// are produced. Otherwise a transaction containing nullifiers and/or note
/// commitments are produced. Dummy transparent UTXOs are sometimes used to make
/// transactions balanced, but it is understood that transparent account changes
/// are effected only by the amounts and signatures specified by the containing
/// Transfer object.
async fn gen_shielded_transfer<C>(
    ctx: &mut C,
    args: &ParsedTxTransferArgs,
    shielded_gas: bool,
) -> Result<Option<(Transaction, TransactionMetadata)>, builder::Error>
where
    C: ShieldedTransferContext,
{
    let spending_key = args.source.spending_key().map(|x| x.into());
    let payment_address = args.target.payment_address();
    // Determine epoch in which to submit potential shielded transaction
    let epoch = ctx.query_epoch(args.tx.ledger_address.clone()).await;
    // Context required for storing which notes are in the source's possesion
    let consensus_branch_id = BranchId::Sapling;
    let amt: u64 = args.amount.into();
    let memo: Option<Memo> = None;

    // Now we build up the transaction within this object
    let mut builder = Builder::<TestNetwork, OsRng>::new(0u32);
    // Convert transaction amount into MASP types
    let (asset_type, amount) = convert_amount(epoch, &args.token, args.amount);

    // Transactions with transparent input and shielded output
    // may be affected if constructed close to epoch boundary
    let mut epoch_sensitive: bool = false;
    // If there are shielded inputs
    if let Some(sk) = spending_key {
        // Transaction fees need to match the amount in the wrapper Transfer
        // when MASP source is used
        let (_, fee) =
            convert_amount(epoch, &args.tx.fee_token, args.tx.fee_amount);
        builder.set_fee(fee.clone())?;
        // If the gas is coming from the shielded pool, then our shielded inputs
        // must also cover the gas fee
        let required_amt = if shielded_gas { amount + fee } else { amount };
        // Locate unspent notes that can help us meet the transaction amount
        let (_, unspent_notes, used_convs) = ctx
            .collect_unspent_notes(
                args.tx.ledger_address.clone(),
                &to_viewing_key(&sk).vk,
                required_amt,
                epoch,
            )
            .await;
        // Commit the notes found to our transaction
        for (diversifier, note, merkle_path) in unspent_notes {
            builder.add_sapling_spend(sk, diversifier, note, merkle_path)?;
        }
        // Commit the conversion notes used during summation
        for (conv, wit, value) in used_convs.values() {
            if *value > 0 {
                builder.add_convert(
                    conv.clone(),
                    *value as u64,
                    wit.clone(),
                )?;
            }
        }
    } else {
        // No transfer fees come from the shielded transaction for non-MASP
        // sources
        builder.set_fee(Amount::zero())?;
        // We add a dummy UTXO to our transaction, but only the source of the
        // parent Transfer object is used to validate fund availability
        let secp_sk =
            secp256k1::SecretKey::from_slice(&[0xcd; 32]).expect("secret key");
        let secp_ctx = secp256k1::Secp256k1::<secp256k1::SignOnly>::gen_new();
        let secp_pk =
            secp256k1::PublicKey::from_secret_key(&secp_ctx, &secp_sk)
                .serialize();
        let hash =
            ripemd160::Ripemd160::digest(&sha2::Sha256::digest(&secp_pk));
        let script = TransparentAddress::PublicKey(hash.into()).script();
        epoch_sensitive = true;
        builder.add_transparent_input(
            secp_sk,
            OutPoint::new([0u8; 32], 0),
            TxOut {
                asset_type,
                value: amt,
                script_pubkey: script,
            },
        )?;
    }
    // Now handle the outputs of this transaction
    // If there is a shielded output
    if let Some(pa) = payment_address {
        let ovk_opt = spending_key.map(|x| x.expsk.ovk);
        builder.add_sapling_output(
            ovk_opt,
            pa.into(),
            asset_type,
            amt,
            memo.clone(),
        )?;
    } else {
        epoch_sensitive = false;
        // Embed the transparent target address into the shielded transaction so
        // that it can be signed
        let target_enc = args
            .target
            .address()
            .expect("target address should be transparent")
            .try_to_vec()
            .expect("target address encoding");
        let hash = ripemd160::Ripemd160::digest(&sha2::Sha256::digest(
            target_enc.as_ref(),
        ));
        builder.add_transparent_output(
            &TransparentAddress::PublicKey(hash.into()),
            asset_type,
            amt,
        )?;
    }
    let prover = if let Ok(params_dir) = env::var(masp::ENV_VAR_MASP_PARAMS_DIR)
    {
        let params_dir = PathBuf::from(params_dir);
        let spend_path = params_dir.join(masp::SPEND_NAME);
        let convert_path = params_dir.join(masp::CONVERT_NAME);
        let output_path = params_dir.join(masp::OUTPUT_NAME);
        LocalTxProver::new(&spend_path, &output_path, &convert_path)
    } else {
        LocalTxProver::with_default_location()
            .expect("unable to load MASP Parameters")
    };
    // Build and return the constructed transaction
    let mut tx = builder.build(consensus_branch_id, &prover);

    if epoch_sensitive {
        let new_epoch = ctx.query_epoch(args.tx.ledger_address.clone()).await;

        // If epoch has changed, recalculate shielded outputs to match new epoch
        if new_epoch != epoch {
            // Hack: build new shielded transfer with updated outputs
            let mut replay_builder = Builder::<TestNetwork, OsRng>::new(0u32);
            replay_builder.set_fee(Amount::zero())?;
            let ovk_opt = spending_key.map(|x| x.expsk.ovk);
            let (new_asset_type, _) =
                convert_amount(new_epoch, &args.token, args.amount);
            replay_builder.add_sapling_output(
                ovk_opt,
                payment_address.unwrap().into(),
                new_asset_type,
                amt,
                memo,
            )?;

            let secp_sk = secp256k1::SecretKey::from_slice(&[0xcd; 32])
                .expect("secret key");
            let secp_ctx =
                secp256k1::Secp256k1::<secp256k1::SignOnly>::gen_new();
            let secp_pk =
                secp256k1::PublicKey::from_secret_key(&secp_ctx, &secp_sk)
                    .serialize();
            let hash =
                ripemd160::Ripemd160::digest(&sha2::Sha256::digest(&secp_pk));
            let script = TransparentAddress::PublicKey(hash.into()).script();
            replay_builder.add_transparent_input(
                secp_sk,
                OutPoint::new([0u8; 32], 0),
                TxOut {
                    asset_type: new_asset_type,
                    value: amt,
                    script_pubkey: script,
                },
            )?;

            let (replay_tx, _) =
                replay_builder.build(consensus_branch_id, &prover)?;
            tx = tx.map(|(t, tm)| {
                let mut temp = t.deref().clone();
                temp.shielded_outputs = replay_tx.shielded_outputs.clone();
                temp.value_balance = temp.value_balance.reject(asset_type)
                    - Amount::from_pair(new_asset_type, amt).unwrap();
                (temp.freeze().unwrap(), tm)
            });
        }
    }

    tx.map(Some)
}

pub async fn submit_transfer(mut ctx: Context, args: args::TxTransfer) {
    let parsed_args = args.parse_from_context(&mut ctx);
    let source = parsed_args.source.effective_address();
    let target = parsed_args.target.effective_address();
    // Check that the source address exists on chain
    let source_exists =
        rpc::known_address(&source, args.tx.ledger_address.clone()).await;
    if !source_exists {
        eprintln!("The source address {} doesn't exist on chain.", source);
        if !args.tx.force {
            safe_exit(1)
        }
    }
    // Check that the target address exists on chain
    let target_exists =
        rpc::known_address(&target, args.tx.ledger_address.clone()).await;
    if !target_exists {
        eprintln!("The target address {} doesn't exist on chain.", target);
        if !args.tx.force {
            safe_exit(1)
        }
    }
    // Check that the token address exists on chain
    let token_exists =
        rpc::known_address(&parsed_args.token, args.tx.ledger_address.clone())
            .await;
    if !token_exists {
        eprintln!(
            "The token address {} doesn't exist on chain.",
            parsed_args.token
        );
        if !args.tx.force {
            safe_exit(1)
        }
    }
    // Check source balance
    let (sub_prefix, balance_key) = match args.sub_prefix {
        Some(sub_prefix) => {
            let sub_prefix = storage::Key::parse(sub_prefix).unwrap();
            let prefix = token::multitoken_balance_prefix(
                &parsed_args.token,
                &sub_prefix,
            );
            (
                Some(sub_prefix),
                token::multitoken_balance_key(&prefix, &source),
            )
        }
        None => (None, token::balance_key(&parsed_args.token, &source)),
    };
    let client = HttpClient::new(args.tx.ledger_address.clone()).unwrap();
    match rpc::query_storage_value::<token::Amount>(&client, &balance_key).await
    {
        Some(balance) => {
            if balance < args.amount {
                eprintln!(
                    "The balance of the source {} of token {} is lower than \
                     the amount to be transferred. Amount to transfer is {} \
                     and the balance is {}.",
                    source, parsed_args.token, args.amount, balance
                );
                if !args.tx.force {
                    safe_exit(1)
                }
            }
        }
        None => {
            eprintln!(
                "No balance found for the source {} of token {}",
                source, parsed_args.token
            );
            if !args.tx.force {
                safe_exit(1)
            }
        }
    };

    let tx_code = ctx.read_wasm(TX_TRANSFER_WASM);
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
                ctx.native_token.clone(),
            )
        } else if source == masp_addr {
            (
                TxSigningKey::SecretKey(masp_tx_key()),
                args.amount,
                parsed_args.token.clone(),
            )
        } else {
            (
                TxSigningKey::WalletAddress(args.source.to_address()),
                args.amount,
                parsed_args.token.clone(),
            )
        };
    // If our chosen signer is the MASP sentinel key, then our shielded inputs
    // will need to cover the gas fees.
    let chosen_signer = tx_signer(&mut ctx, &args.tx, default_signer.clone())
        .await
        .ref_to();
    let shielded_gas = masp_tx_key().ref_to() == chosen_signer;
    // Determine whether to pin this transaction to a storage key
    let key = match ctx.get(&args.target) {
        TransferTarget::PaymentAddress(pa) if pa.is_pinned() => Some(pa.hash()),
        _ => None,
    };

    let transfer = token::Transfer {
        source,
        target,
        token,
        sub_prefix,
        amount,
        key,
        shielded: {
            let spending_key = parsed_args.source.spending_key();
            let payment_address = parsed_args.target.payment_address();
            // No shielded components are needed when neither source nor
            // destination are shielded
            if spending_key.is_none() && payment_address.is_none() {
                None
            } else {
                // We want to fund our transaction solely from supplied spending
                // key
                let spending_key = spending_key.map(|x| x.into());
                let spending_keys: Vec<_> = spending_key.into_iter().collect();
                // Load the current shielded context given the spending key we
                // possess
                let _ = ctx.shielded.load();
                ctx.shielded
                    .fetch(&args.tx.ledger_address, &spending_keys, &[])
                    .await;
                // Save the update state so that future fetches can be
                // short-circuited
                let _ = ctx.shielded.save();
                let stx_result =
                    gen_shielded_transfer(&mut ctx, &parsed_args, shielded_gas)
                        .await;
                match stx_result {
                    Ok(stx) => stx.map(|x| x.0),
                    Err(builder::Error::ChangeIsNegative(_)) => {
                        eprintln!(
                            "The balance of the source {} is lower than the \
                             amount to be transferred and fees. Amount to \
                             transfer is {} {} and fees are {} {}.",
                            parsed_args.source,
                            args.amount,
                            parsed_args.token,
                            args.tx.fee_amount,
                            parsed_args.tx.fee_token,
                        );
                        safe_exit(1)
                    }
                    Err(err) => panic!("{}", err),
                }
            }
        },
    };
    tracing::debug!("Transfer data {:?}", transfer);
    let data = transfer
        .try_to_vec()
        .expect("Encoding tx data shouldn't fail");

    let tx = Tx::new(tx_code, Some(data));
    let signing_address = TxSigningKey::WalletAddress(args.source.to_address());
    process_tx(ctx, &args.tx, tx, signing_address).await;
}

pub async fn submit_ibc_transfer(ctx: Context, args: args::TxIbcTransfer) {
    let source = ctx.get(&args.source);
    // Check that the source address exists on chain
    let source_exists =
        rpc::known_address(&source, args.tx.ledger_address.clone()).await;
    if !source_exists {
        eprintln!("The source address {} doesn't exist on chain.", source);
        if !args.tx.force {
            safe_exit(1)
        }
    }

    // We cannot check the receiver

    let token = ctx.get(&args.token);
    // Check that the token address exists on chain
    let token_exists =
        rpc::known_address(&token, args.tx.ledger_address.clone()).await;
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
    let client = HttpClient::new(args.tx.ledger_address.clone()).unwrap();
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
    let tx_code = ctx.read_wasm(TX_IBC_WASM);

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
    process_tx(ctx, &args.tx, tx, TxSigningKey::WalletAddress(args.source))
        .await;
}

pub async fn submit_init_proposal(mut ctx: Context, args: args::InitProposal) {
=======
/// Make shielded components to embed within a Transfer object. If no shielded
/// payment address nor spending key is specified, then no shielded components
/// are produced. Otherwise a transaction containing nullifiers and/or note
/// commitments are produced. Dummy transparent UTXOs are sometimes used to make
/// transactions balanced, but it is understood that transparent account changes
/// are effected only by the amounts and signatures specified by the containing
/// Transfer object.
async fn gen_shielded_transfer<C>(
    ctx: &mut C,
    args: &ParsedTxTransferArgs,
    shielded_gas: bool,
) -> Result<Option<(Transaction, TransactionMetadata)>, builder::Error>
where
    C: ShieldedTransferContext,
{
    let spending_key = args.source.spending_key().map(|x| x.into());
    let payment_address = args.target.payment_address();
    // Determine epoch in which to submit potential shielded transaction
    let epoch = ctx.query_epoch(args.tx.ledger_address.clone()).await;
    // Context required for storing which notes are in the source's possesion
    let consensus_branch_id = BranchId::Sapling;
    let amt: u64 = args.amount.into();
    let memo: Option<Memo> = None;

    // Now we build up the transaction within this object
    let mut builder = Builder::<TestNetwork, OsRng>::new(0u32);
    // Convert transaction amount into MASP types
    let (asset_type, amount) = convert_amount(epoch, &args.token, args.amount);

    // Transactions with transparent input and shielded output
    // may be affected if constructed close to epoch boundary
    let mut epoch_sensitive: bool = false;
    // If there are shielded inputs
    if let Some(sk) = spending_key {
        // Transaction fees need to match the amount in the wrapper Transfer
        // when MASP source is used
        let (_, fee) =
            convert_amount(epoch, &args.tx.fee_token, args.tx.fee_amount);
        builder.set_fee(fee.clone())?;
        // If the gas is coming from the shielded pool, then our shielded inputs
        // must also cover the gas fee
        let required_amt = if shielded_gas { amount + fee } else { amount };
        // Locate unspent notes that can help us meet the transaction amount
        let (_, unspent_notes, used_convs) = ctx
            .collect_unspent_notes(
                args.tx.ledger_address.clone(),
                &to_viewing_key(&sk).vk,
                required_amt,
                epoch,
            )
            .await;
        // Commit the notes found to our transaction
        for (diversifier, note, merkle_path) in unspent_notes {
            builder.add_sapling_spend(sk, diversifier, note, merkle_path)?;
        }
        // Commit the conversion notes used during summation
        for (conv, wit, value) in used_convs.values() {
            if *value > 0 {
                builder.add_convert(
                    conv.clone(),
                    *value as u64,
                    wit.clone(),
                )?;
            }
        }
    } else {
        // No transfer fees come from the shielded transaction for non-MASP
        // sources
        builder.set_fee(Amount::zero())?;
        // We add a dummy UTXO to our transaction, but only the source of the
        // parent Transfer object is used to validate fund availability
        let secp_sk =
            secp256k1::SecretKey::from_slice(&[0xcd; 32]).expect("secret key");
        let secp_ctx = secp256k1::Secp256k1::<secp256k1::SignOnly>::gen_new();
        let secp_pk =
            secp256k1::PublicKey::from_secret_key(&secp_ctx, &secp_sk)
                .serialize();
        let hash =
            ripemd160::Ripemd160::digest(&sha2::Sha256::digest(&secp_pk));
        let script = TransparentAddress::PublicKey(hash.into()).script();
        epoch_sensitive = true;
        builder.add_transparent_input(
            secp_sk,
            OutPoint::new([0u8; 32], 0),
            TxOut {
                asset_type,
                value: amt,
                script_pubkey: script,
            },
        )?;
    }
    // Now handle the outputs of this transaction
    // If there is a shielded output
    if let Some(pa) = payment_address {
        let ovk_opt = spending_key.map(|x| x.expsk.ovk);
        builder.add_sapling_output(
            ovk_opt,
            pa.into(),
            asset_type,
            amt,
            memo.clone(),
        )?;
    } else {
        epoch_sensitive = false;
        // Embed the transparent target address into the shielded transaction so
        // that it can be signed
        let target_enc = args
            .target
            .address()
            .expect("target address should be transparent")
            .try_to_vec()
            .expect("target address encoding");
        let hash = ripemd160::Ripemd160::digest(&sha2::Sha256::digest(
            target_enc.as_ref(),
        ));
        builder.add_transparent_output(
            &TransparentAddress::PublicKey(hash.into()),
            asset_type,
            amt,
        )?;
    }
    let prover = if let Ok(params_dir) = env::var(masp::ENV_VAR_MASP_PARAMS_DIR)
    {
        let params_dir = PathBuf::from(params_dir);
        let spend_path = params_dir.join(masp::SPEND_NAME);
        let convert_path = params_dir.join(masp::CONVERT_NAME);
        let output_path = params_dir.join(masp::OUTPUT_NAME);
        LocalTxProver::new(&spend_path, &output_path, &convert_path)
    } else {
        LocalTxProver::with_default_location()
            .expect("unable to load MASP Parameters")
    };
    // Build and return the constructed transaction
    let mut tx = builder.build(consensus_branch_id, &prover);

    if epoch_sensitive {
        let new_epoch = ctx.query_epoch(args.tx.ledger_address.clone()).await;

        // If epoch has changed, recalculate shielded outputs to match new epoch
        if new_epoch != epoch {
            // Hack: build new shielded transfer with updated outputs
            let mut replay_builder = Builder::<TestNetwork, OsRng>::new(0u32);
            replay_builder.set_fee(Amount::zero())?;
            let ovk_opt = spending_key.map(|x| x.expsk.ovk);
            let (new_asset_type, _) =
                convert_amount(new_epoch, &args.token, args.amount);
            replay_builder.add_sapling_output(
                ovk_opt,
                payment_address.unwrap().into(),
                new_asset_type,
                amt,
                memo,
            )?;

            let secp_sk = secp256k1::SecretKey::from_slice(&[0xcd; 32])
                .expect("secret key");
            let secp_ctx =
                secp256k1::Secp256k1::<secp256k1::SignOnly>::gen_new();
            let secp_pk =
                secp256k1::PublicKey::from_secret_key(&secp_ctx, &secp_sk)
                    .serialize();
            let hash =
                ripemd160::Ripemd160::digest(&sha2::Sha256::digest(&secp_pk));
            let script = TransparentAddress::PublicKey(hash.into()).script();
            replay_builder.add_transparent_input(
                secp_sk,
                OutPoint::new([0u8; 32], 0),
                TxOut {
                    asset_type: new_asset_type,
                    value: amt,
                    script_pubkey: script,
                },
            )?;

            let (replay_tx, _) =
                replay_builder.build(consensus_branch_id, &prover)?;
            tx = tx.map(|(t, tm)| {
                let mut temp = t.deref().clone();
                temp.shielded_outputs = replay_tx.shielded_outputs.clone();
                temp.value_balance = temp.value_balance.reject(asset_type)
                    - Amount::from_pair(new_asset_type, amt).unwrap();
                (temp.freeze().unwrap(), tm)
            });
        }
    }

    tx.map(Some)
}

pub async fn submit_transfer(mut ctx: Context, args: args::TxTransfer) {
    let parsed_args = args.parse_from_context(&mut ctx);
    let source = parsed_args.source.effective_address();
    let target = parsed_args.target.effective_address();
    // Check that the source address exists on chain
    let source_exists =
        rpc::known_address(&source, args.tx.ledger_address.clone()).await;
    if !source_exists {
        eprintln!("The source address {} doesn't exist on chain.", source);
        if !args.tx.force {
            safe_exit(1)
        }
    }
    // Check that the target address exists on chain
    let target_exists =
        rpc::known_address(&target, args.tx.ledger_address.clone()).await;
    if !target_exists {
        eprintln!("The target address {} doesn't exist on chain.", target);
        if !args.tx.force {
            safe_exit(1)
        }
    }
    // Check that the token address exists on chain
    let token_exists =
        rpc::known_address(&parsed_args.token, args.tx.ledger_address.clone())
            .await;
    if !token_exists {
        eprintln!(
            "The token address {} doesn't exist on chain.",
            parsed_args.token
        );
        if !args.tx.force {
            safe_exit(1)
        }
    }
    // Check source balance
    let (sub_prefix, balance_key) = match args.sub_prefix {
        Some(sub_prefix) => {
            let sub_prefix = storage::Key::parse(sub_prefix).unwrap();
            let prefix = token::multitoken_balance_prefix(
                &parsed_args.token,
                &sub_prefix,
            );
            (
                Some(sub_prefix),
                token::multitoken_balance_key(&prefix, &source),
            )
        }
        None => (None, token::balance_key(&parsed_args.token, &source)),
    };
    let client = HttpClient::new(args.tx.ledger_address.clone()).unwrap();
    match rpc::query_storage_value::<token::Amount>(&client, &balance_key).await
    {
        Some(balance) => {
            if balance < args.amount {
                eprintln!(
                    "The balance of the source {} of token {} is lower than \
                     the amount to be transferred. Amount to transfer is {} \
                     and the balance is {}.",
                    source, parsed_args.token, args.amount, balance
                );
                if !args.tx.force {
                    safe_exit(1)
                }
            }
        }
        None => {
            eprintln!(
                "No balance found for the source {} of token {}",
                source, parsed_args.token
            );
            if !args.tx.force {
                safe_exit(1)
            }
        }
    };

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
                ctx.native_token.clone(),
            )
        } else if source == masp_addr {
            (
                TxSigningKey::SecretKey(masp_tx_key()),
                args.amount,
                parsed_args.token.clone(),
            )
        } else {
            (
                TxSigningKey::WalletAddress(args.source.to_address()),
                args.amount,
                parsed_args.token.clone(),
            )
        };
    // If our chosen signer is the MASP sentinel key, then our shielded inputs
    // will need to cover the gas fees.
    let chosen_signer = tx_signer(&mut ctx, &args.tx, default_signer.clone())
        .await
        .ref_to();
    let shielded_gas = masp_tx_key().ref_to() == chosen_signer;
    // Determine whether to pin this transaction to a storage key
    let key = match ctx.get(&args.target) {
        TransferTarget::PaymentAddress(pa) if pa.is_pinned() => Some(pa.hash()),
        _ => None,
    };

    #[cfg(not(feature = "mainnet"))]
    let is_source_faucet =
        rpc::is_faucet_account(&source, args.tx.ledger_address.clone()).await;

    let transfer = token::Transfer {
        source,
        target,
        token,
        sub_prefix,
        amount,
        key,
        shielded: {
            let spending_key = parsed_args.source.spending_key();
            let payment_address = parsed_args.target.payment_address();
            // No shielded components are needed when neither source nor
            // destination are shielded
            if spending_key.is_none() && payment_address.is_none() {
                None
            } else {
                // We want to fund our transaction solely from supplied spending
                // key
                let spending_key = spending_key.map(|x| x.into());
                let spending_keys: Vec<_> = spending_key.into_iter().collect();
                // Load the current shielded context given the spending key we
                // possess
                let _ = ctx.shielded.load();
                ctx.shielded
                    .fetch(&args.tx.ledger_address, &spending_keys, &[])
                    .await;
                // Save the update state so that future fetches can be
                // short-circuited
                let _ = ctx.shielded.save();
                let stx_result =
                    gen_shielded_transfer(&mut ctx, &parsed_args, shielded_gas)
                        .await;
                match stx_result {
                    Ok(stx) => stx.map(|x| x.0),
                    Err(builder::Error::ChangeIsNegative(_)) => {
                        eprintln!(
                            "The balance of the source {} is lower than the \
                             amount to be transferred and fees. Amount to \
                             transfer is {} {} and fees are {} {}.",
                            parsed_args.source,
                            args.amount,
                            parsed_args.token,
                            args.tx.fee_amount,
                            parsed_args.tx.fee_token,
                        );
                        safe_exit(1)
                    }
                    Err(err) => panic!("{}", err),
                }
            }
        },
    };
    tracing::debug!("Transfer data {:?}", transfer);
    let data = transfer
        .try_to_vec()
        .expect("Encoding tx data shouldn't fail");
    let tx_code = ctx.read_wasm(TX_TRANSFER_WASM);
    let tx = Tx::new(tx_code, Some(data));
    let signing_address = TxSigningKey::WalletAddress(args.source.to_address());

    process_tx(
        ctx,
        &args.tx,
        tx,
        signing_address,
        #[cfg(not(feature = "mainnet"))]
        is_source_faucet,
    )
    .await;
}

pub async fn submit_ibc_transfer(ctx: Context, args: args::TxIbcTransfer) {
    let source = ctx.get(&args.source);
    // Check that the source address exists on chain
    let source_exists =
        rpc::known_address(&source, args.tx.ledger_address.clone()).await;
    if !source_exists {
        eprintln!("The source address {} doesn't exist on chain.", source);
        if !args.tx.force {
            safe_exit(1)
        }
    }

    // We cannot check the receiver

    let token = ctx.get(&args.token);
    // Check that the token address exists on chain
    let token_exists =
        rpc::known_address(&token, args.tx.ledger_address.clone()).await;
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
    let client = HttpClient::new(args.tx.ledger_address.clone()).unwrap();
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
    let tx_code = ctx.read_wasm(TX_IBC_WASM);

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
    process_tx(
        ctx,
        &args.tx,
        tx,
        TxSigningKey::WalletAddress(args.source),
        #[cfg(not(feature = "mainnet"))]
        false,
    )
    .await;
}

pub async fn submit_init_proposal(mut ctx: Context, args: args::InitProposal) {
>>>>>>> v0.13.0
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

<<<<<<< HEAD
        process_tx::<C, CliWalletUtils>(
            client,
            &mut ctx.wallet,
            &args.tx,
            tx,
            TxSigningKey::WalletAddress(signer),
        )
        .await?;
        Ok(())
||||||| f6262aa20
        process_tx(ctx, &args.tx, tx, TxSigningKey::WalletAddress(signer))
            .await;
=======
        process_tx(
            ctx,
            &args.tx,
            tx,
            TxSigningKey::WalletAddress(signer),
            #[cfg(not(feature = "mainnet"))]
            false,
        )
        .await;
>>>>>>> v0.13.0
    }
}

pub async fn submit_vote_proposal<
    C: namada::ledger::queries::Client + Sync,
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
        let proposal_file_path = args.proposal_data.ok_or(tx::Error::Other(
            "Proposal file should exist.".to_string(),
        ))?;
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

        let signing_key = find_keypair::<C, U>(client, wallet, signer).await?;
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
            client,
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

pub async fn submit_reveal_pk<
    C: namada::ledger::queries::Client + Sync,
    U: WalletUtils,
>(
    client: &C,
    wallet: &mut Wallet<U>,
    args: args::RevealPk,
) -> Result<(), tx::Error> {
    tx::submit_reveal_pk::<C, U>(client, wallet, args).await
}

pub async fn reveal_pk_if_needed<
    C: namada::ledger::queries::Client + Sync,
    U: WalletUtils,
>(
    client: &C,
    wallet: &mut Wallet<U>,
    public_key: &common::PublicKey,
    args: &args::Tx,
) -> Result<bool, tx::Error> {
    tx::reveal_pk_if_needed::<C, U>(client, wallet, public_key, args).await
}

pub async fn has_revealed_pk<C: namada::ledger::queries::Client + Sync>(
    client: &C,
    addr: &Address,
) -> bool {
    tx::has_revealed_pk(client, addr).await
}

pub async fn submit_reveal_pk_aux<
    C: namada::ledger::queries::Client + Sync,
    U: WalletUtils,
>(
    client: &C,
    wallet: &mut Wallet<U>,
    public_key: &common::PublicKey,
    args: &args::Tx,
<<<<<<< HEAD
) -> Result<(), tx::Error> {
    tx::submit_reveal_pk_aux::<C, U>(client, wallet, public_key, args).await
||||||| f6262aa20
) {
    let addr: Address = public_key.into();
    println!("Submitting a tx to reveal the public key for address {addr}...");
    let tx_data = public_key
        .try_to_vec()
        .expect("Encoding a public key shouldn't fail");
    let tx_code = ctx.read_wasm(TX_REVEAL_PK);
    let tx = Tx::new(tx_code, Some(tx_data));

    // submit_tx without signing the inner tx
    let keypair = if let Some(signing_key) = &args.signing_key {
        ctx.get_cached(signing_key)
    } else if let Some(signer) = args.signer.as_ref() {
        let signer = ctx.get(signer);
        find_keypair(&mut ctx.wallet, &signer, args.ledger_address.clone())
            .await
    } else {
        find_keypair(&mut ctx.wallet, &addr, args.ledger_address.clone()).await
    };
    let epoch = rpc::query_epoch(args::Query {
        ledger_address: args.ledger_address.clone(),
    })
    .await;
    let to_broadcast = if args.dry_run {
        TxBroadcastData::DryRun(tx)
    } else {
        super::signing::sign_wrapper(ctx, args, epoch, tx, &keypair).await
    };

    if args.dry_run {
        if let TxBroadcastData::DryRun(tx) = to_broadcast {
            rpc::dry_run_tx(&args.ledger_address, tx.to_bytes()).await;
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
            Left(broadcast_tx(args.ledger_address.clone(), &to_broadcast).await)
        } else {
            Right(submit_tx(args.ledger_address.clone(), to_broadcast).await)
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
=======
) {
    let addr: Address = public_key.into();
    println!("Submitting a tx to reveal the public key for address {addr}...");
    let tx_data = public_key
        .try_to_vec()
        .expect("Encoding a public key shouldn't fail");
    let tx_code = ctx.read_wasm(TX_REVEAL_PK);
    let tx = Tx::new(tx_code, Some(tx_data));

    // submit_tx without signing the inner tx
    let keypair = if let Some(signing_key) = &args.signing_key {
        ctx.get_cached(signing_key)
    } else if let Some(signer) = args.signer.as_ref() {
        let signer = ctx.get(signer);
        find_keypair(&mut ctx.wallet, &signer, args.ledger_address.clone())
            .await
    } else {
        find_keypair(&mut ctx.wallet, &addr, args.ledger_address.clone()).await
    };
    let epoch = rpc::query_epoch(args::Query {
        ledger_address: args.ledger_address.clone(),
    })
    .await;
    let to_broadcast = if args.dry_run {
        TxBroadcastData::DryRun(tx)
    } else {
        super::signing::sign_wrapper(
            ctx,
            args,
            epoch,
            tx,
            &keypair,
            #[cfg(not(feature = "mainnet"))]
            false,
        )
        .await
    };

    if args.dry_run {
        if let TxBroadcastData::DryRun(tx) = to_broadcast {
            rpc::dry_run_tx(&args.ledger_address, tx.to_bytes()).await;
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
            Left(broadcast_tx(args.ledger_address.clone(), &to_broadcast).await)
        } else {
            Right(submit_tx(args.ledger_address.clone(), to_broadcast).await)
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
>>>>>>> v0.13.0
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

<<<<<<< HEAD
pub async fn submit_bond<
    C: namada::ledger::queries::Client + Sync,
    U: WalletUtils,
>(
    client: &C,
    wallet: &mut Wallet<U>,
    args: args::Bond,
) -> Result<(), tx::Error> {
    tx::submit_bond::<C, U>(client, wallet, args).await
||||||| f6262aa20
pub async fn submit_bond(ctx: Context, args: args::Bond) {
    let validator = ctx.get(&args.validator);
    // Check that the validator address exists on chain
    let is_validator =
        rpc::is_validator(&validator, args.tx.ledger_address.clone()).await;
    if !is_validator {
        eprintln!(
            "The address {} doesn't belong to any known validator account.",
            validator
        );
        if !args.tx.force {
            safe_exit(1)
        }
    }
    let source = ctx.get_opt(&args.source);
    // Check that the source address exists on chain
    if let Some(source) = &source {
        let source_exists =
            rpc::known_address(source, args.tx.ledger_address.clone()).await;
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
    let balance_key = token::balance_key(&ctx.native_token, bond_source);
    let client = HttpClient::new(args.tx.ledger_address.clone()).unwrap();
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
    let tx_code = ctx.read_wasm(TX_BOND_WASM);
    let bond = pos::Bond {
        validator,
        amount: args.amount,
        source,
    };
    let data = bond.try_to_vec().expect("Encoding tx data shouldn't fail");

    let tx = Tx::new(tx_code, Some(data));
    let default_signer = args.source.unwrap_or(args.validator);
    process_tx(
        ctx,
        &args.tx,
        tx,
        TxSigningKey::WalletAddress(default_signer),
    )
    .await;
=======
pub async fn submit_bond(ctx: Context, args: args::Bond) {
    let validator = ctx.get(&args.validator);
    // Check that the validator address exists on chain
    let is_validator =
        rpc::is_validator(&validator, args.tx.ledger_address.clone()).await;
    if !is_validator {
        eprintln!(
            "The address {} doesn't belong to any known validator account.",
            validator
        );
        if !args.tx.force {
            safe_exit(1)
        }
    }
    let source = ctx.get_opt(&args.source);
    // Check that the source address exists on chain
    if let Some(source) = &source {
        let source_exists =
            rpc::known_address(source, args.tx.ledger_address.clone()).await;
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
    let balance_key = token::balance_key(&ctx.native_token, bond_source);
    let client = HttpClient::new(args.tx.ledger_address.clone()).unwrap();
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
    let tx_code = ctx.read_wasm(TX_BOND_WASM);
    let bond = pos::Bond {
        validator,
        amount: args.amount,
        source,
    };
    let data = bond.try_to_vec().expect("Encoding tx data shouldn't fail");

    let tx = Tx::new(tx_code, Some(data));
    let default_signer = args.source.unwrap_or(args.validator);
    process_tx(
        ctx,
        &args.tx,
        tx,
        TxSigningKey::WalletAddress(default_signer),
        #[cfg(not(feature = "mainnet"))]
        false,
    )
    .await;
>>>>>>> v0.13.0
}

<<<<<<< HEAD
pub async fn submit_unbond<
    C: namada::ledger::queries::Client + Sync,
    U: WalletUtils,
>(
    client: &C,
    wallet: &mut Wallet<U>,
    args: args::Unbond,
) -> Result<(), tx::Error> {
    tx::submit_unbond::<C, U>(client, wallet, args).await
||||||| f6262aa20
pub async fn submit_unbond(ctx: Context, args: args::Unbond) {
    let validator = ctx.get(&args.validator);
    // Check that the validator address exists on chain
    let is_validator =
        rpc::is_validator(&validator, args.tx.ledger_address.clone()).await;
    if !is_validator {
        eprintln!(
            "The address {} doesn't belong to any known validator account.",
            validator
        );
        if !args.tx.force {
            safe_exit(1)
        }
    }

    let source = ctx.get_opt(&args.source);
    let tx_code = ctx.read_wasm(TX_UNBOND_WASM);

    // Check the source's current bond amount
    let bond_source = source.clone().unwrap_or_else(|| validator.clone());
    let bond_id = BondId {
        source: bond_source.clone(),
        validator: validator.clone(),
    };
    let bond_key = ledger::pos::bond_key(&bond_id);
    let client = HttpClient::new(args.tx.ledger_address.clone()).unwrap();
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
        ctx,
        &args.tx,
        tx,
        TxSigningKey::WalletAddress(default_signer),
    )
    .await;
=======
pub async fn submit_unbond(ctx: Context, args: args::Unbond) {
    let validator = ctx.get(&args.validator);
    // Check that the validator address exists on chain
    let is_validator =
        rpc::is_validator(&validator, args.tx.ledger_address.clone()).await;
    if !is_validator {
        eprintln!(
            "The address {} doesn't belong to any known validator account.",
            validator
        );
        if !args.tx.force {
            safe_exit(1)
        }
    }

    let source = ctx.get_opt(&args.source);
    let tx_code = ctx.read_wasm(TX_UNBOND_WASM);

    // Check the source's current bond amount
    let bond_source = source.clone().unwrap_or_else(|| validator.clone());
    let bond_id = BondId {
        source: bond_source.clone(),
        validator: validator.clone(),
    };
    let bond_key = ledger::pos::bond_key(&bond_id);
    let client = HttpClient::new(args.tx.ledger_address.clone()).unwrap();
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
        ctx,
        &args.tx,
        tx,
        TxSigningKey::WalletAddress(default_signer),
        #[cfg(not(feature = "mainnet"))]
        false,
    )
    .await;
>>>>>>> v0.13.0
}

<<<<<<< HEAD
pub async fn submit_withdraw<
    C: namada::ledger::queries::Client + Sync,
    U: WalletUtils,
>(
    client: &C,
    wallet: &mut Wallet<U>,
    args: args::Withdraw,
) -> Result<(), tx::Error> {
    tx::submit_withdraw::<C, U>(client, wallet, args).await
||||||| f6262aa20
pub async fn submit_withdraw(ctx: Context, args: args::Withdraw) {
    let epoch = rpc::query_epoch(args::Query {
        ledger_address: args.tx.ledger_address.clone(),
    })
    .await;

    let validator = ctx.get(&args.validator);
    // Check that the validator address exists on chain
    let is_validator =
        rpc::is_validator(&validator, args.tx.ledger_address.clone()).await;
    if !is_validator {
        eprintln!(
            "The address {} doesn't belong to any known validator account.",
            validator
        );
        if !args.tx.force {
            safe_exit(1)
        }
    }

    let source = ctx.get_opt(&args.source);
    let tx_code = ctx.read_wasm(TX_WITHDRAW_WASM);

    // Check the source's current unbond amount
    let bond_source = source.clone().unwrap_or_else(|| validator.clone());
    let bond_id = BondId {
        source: bond_source.clone(),
        validator: validator.clone(),
    };
    let bond_key = ledger::pos::unbond_key(&bond_id);
    let client = HttpClient::new(args.tx.ledger_address.clone()).unwrap();
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
        ctx,
        &args.tx,
        tx,
        TxSigningKey::WalletAddress(default_signer),
    )
    .await;
=======
pub async fn submit_withdraw(ctx: Context, args: args::Withdraw) {
    let epoch = rpc::query_epoch(args::Query {
        ledger_address: args.tx.ledger_address.clone(),
    })
    .await;

    let validator = ctx.get(&args.validator);
    // Check that the validator address exists on chain
    let is_validator =
        rpc::is_validator(&validator, args.tx.ledger_address.clone()).await;
    if !is_validator {
        eprintln!(
            "The address {} doesn't belong to any known validator account.",
            validator
        );
        if !args.tx.force {
            safe_exit(1)
        }
    }

    let source = ctx.get_opt(&args.source);
    let tx_code = ctx.read_wasm(TX_WITHDRAW_WASM);

    // Check the source's current unbond amount
    let bond_source = source.clone().unwrap_or_else(|| validator.clone());
    let bond_id = BondId {
        source: bond_source.clone(),
        validator: validator.clone(),
    };
    let bond_key = ledger::pos::unbond_key(&bond_id);
    let client = HttpClient::new(args.tx.ledger_address.clone()).unwrap();
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
        ctx,
        &args.tx,
        tx,
        TxSigningKey::WalletAddress(default_signer),
        #[cfg(not(feature = "mainnet"))]
        false,
    )
    .await;
>>>>>>> v0.13.0
}

pub async fn submit_validator_commission_change<
    C: namada::ledger::queries::Client + Sync,
    U: WalletUtils,
>(
    client: &C,
    wallet: &mut Wallet<U>,
    args: args::TxCommissionRateChange,
<<<<<<< HEAD
) -> Result<(), tx::Error> {
    tx::submit_validator_commission_change::<C, U>(client, wallet, args).await
||||||| f6262aa20
) {
    let epoch = rpc::query_epoch(args::Query {
        ledger_address: args.tx.ledger_address.clone(),
    })
    .await;

    let tx_code = ctx.read_wasm(TX_CHANGE_COMMISSION_WASM);
    let client = HttpClient::new(args.tx.ledger_address.clone()).unwrap();

    let validator = ctx.get(&args.validator);
    if rpc::is_validator(&validator, args.tx.ledger_address.clone()).await {
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
        validator: ctx.get(&args.validator),
        new_rate: args.rate,
    };
    let data = data.try_to_vec().expect("Encoding tx data shouldn't fail");

    let tx = Tx::new(tx_code, Some(data));
    let default_signer = args.validator;
    process_tx(
        ctx,
        &args.tx,
        tx,
        TxSigningKey::WalletAddress(default_signer),
    )
    .await;
=======
) {
    let epoch = rpc::query_epoch(args::Query {
        ledger_address: args.tx.ledger_address.clone(),
    })
    .await;

    let tx_code = ctx.read_wasm(TX_CHANGE_COMMISSION_WASM);
    let client = HttpClient::new(args.tx.ledger_address.clone()).unwrap();

    let validator = ctx.get(&args.validator);
    if rpc::is_validator(&validator, args.tx.ledger_address.clone()).await {
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
        validator: ctx.get(&args.validator),
        new_rate: args.rate,
    };
    let data = data.try_to_vec().expect("Encoding tx data shouldn't fail");

    let tx = Tx::new(tx_code, Some(data));
    let default_signer = args.validator;
    process_tx(
        ctx,
        &args.tx,
        tx,
        TxSigningKey::WalletAddress(default_signer),
        #[cfg(not(feature = "mainnet"))]
        false,
    )
    .await;
>>>>>>> v0.13.0
}

/// Submit transaction and wait for result. Returns a list of addresses
/// initialized in the transaction if any. In dry run, this is always empty.
async fn process_tx<
    C: namada::ledger::queries::Client + Sync,
    U: WalletUtils,
>(
    client: &C,
    wallet: &mut Wallet<U>,
    args: &args::Tx,
    tx: Tx,
    default_signer: TxSigningKey,
<<<<<<< HEAD
) -> Result<Vec<Address>, tx::Error> {
    tx::process_tx::<C, U>(client, wallet, args, tx, default_signer).await
||||||| f6262aa20
) -> (Context, Vec<Address>) {
    let (ctx, to_broadcast) = sign_tx(ctx, tx, args, default_signer).await;
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
            rpc::dry_run_tx(&args.ledger_address, tx.to_bytes()).await;
            (ctx, vec![])
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
            Left(broadcast_tx(args.ledger_address.clone(), &to_broadcast).await)
        } else {
            Right(submit_tx(args.ledger_address.clone(), to_broadcast).await)
        };
        // Return result based on executed operation, otherwise deal with
        // the encountered errors uniformly
        match result {
            Right(Ok(result)) => (ctx, result.initialized_accounts),
            Left(Ok(_)) => (ctx, Vec::default()),
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
=======
    #[cfg(not(feature = "mainnet"))] requires_pow: bool,
) -> (Context, Vec<Address>) {
    let (ctx, to_broadcast) = sign_tx(
        ctx,
        tx,
        args,
        default_signer,
        #[cfg(not(feature = "mainnet"))]
        requires_pow,
    )
    .await;
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
            rpc::dry_run_tx(&args.ledger_address, tx.to_bytes()).await;
            (ctx, vec![])
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
            Left(broadcast_tx(args.ledger_address.clone(), &to_broadcast).await)
        } else {
            Right(submit_tx(args.ledger_address.clone(), to_broadcast).await)
        };
        // Return result based on executed operation, otherwise deal with
        // the encountered errors uniformly
        match result {
            Right(Ok(result)) => (ctx, result.initialized_accounts),
            Left(Ok(_)) => (ctx, Vec::default()),
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
>>>>>>> v0.13.0
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
