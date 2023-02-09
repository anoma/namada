use std::borrow::Cow;
use std::collections::hash_map::Entry;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::env;
use std::fmt::Debug;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::ops::Deref;
use std::path::PathBuf;

use async_std::io::prelude::WriteExt;
use async_std::io::{self};
use borsh::{BorshDeserialize, BorshSerialize};
use itertools::Either::*;
use masp_primitives::asset_type::AssetType;
use masp_primitives::consensus::{BranchId, TestNetwork};
use masp_primitives::convert::AllowedConversion;
use masp_primitives::ff::PrimeField;
use masp_primitives::group::cofactor::CofactorGroup;
use masp_primitives::keys::FullViewingKey;
use masp_primitives::legacy::TransparentAddress;
use masp_primitives::merkle_tree::{
    CommitmentTree, IncrementalWitness, MerklePath,
};
use masp_primitives::note_encryption::*;
use masp_primitives::primitives::{Diversifier, Note, ViewingKey};
use masp_primitives::sapling::Node;
use masp_primitives::transaction::builder::{self, secp256k1, *};
use masp_primitives::transaction::components::{Amount, OutPoint, TxOut};
use masp_primitives::transaction::Transaction;
use masp_primitives::zip32::{ExtendedFullViewingKey, ExtendedSpendingKey};
use masp_proofs::prover::LocalTxProver;
use namada::ibc::applications::ics20_fungible_token_transfer::msgs::transfer::MsgTransfer;
use namada::ibc::signer::Signer;
use namada::ibc::timestamp::Timestamp as IbcTimestamp;
use namada::ibc::tx_msg::Msg;
use namada::ibc::Height as IbcHeight;
use namada::ibc_proto::cosmos::base::v1beta1::Coin;
use namada::ledger::governance::storage as gov_storage;
use namada::ledger::masp;
use namada::ledger::pos::{CommissionPair, PosParams};
use namada::proto::Tx;
use namada::types::address::{masp, masp_tx_key, Address};
use namada::types::governance::{
    OfflineProposal, OfflineVote, Proposal, ProposalVote,
};
use namada::types::key::*;
use namada::types::masp::{PaymentAddress, TransferTarget};
use namada::types::storage::{
    BlockHeight, Epoch, Key, KeySeg, TxIndex, RESERVED_ADDRESS_PREFIX,
};
use namada::types::time::DateTimeUtc;
use namada::types::token::{
    Transfer, HEAD_TX_KEY, PIN_KEY_PREFIX, TX_KEY_PREFIX,
};
use namada::types::transaction::governance::{
    InitProposalData, VoteProposalData,
};
use namada::types::transaction::{pos, InitAccount, InitValidator, UpdateVp};
use namada::types::{storage, token};
use namada::vm;
use rand_core::{CryptoRng, OsRng, RngCore};
use rust_decimal::Decimal;
use sha2::Digest;
use tokio::time::{Duration, Instant};

use super::rpc;
use super::types::ShieldedTransferContext;
use crate::cli::context::WalletAddress;
use crate::cli::{args, safe_exit, Context};
use crate::client::rpc::{query_conversion, query_storage_value};
use crate::client::signing::{find_keypair, sign_tx, tx_signer, TxSigningKey};
use crate::client::tendermint_rpc_types::{TxBroadcastData, TxResponse};
use crate::client::types::ParsedTxTransferArgs;
use crate::facade::tendermint_config::net::Address as TendermintAddress;
use crate::facade::tendermint_rpc::endpoint::broadcast::tx_sync::Response;
use crate::facade::tendermint_rpc::error::Error as RpcError;
use crate::facade::tendermint_rpc::{Client, HttpClient};
use crate::node::ledger::tendermint_node;

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
}

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
}

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
}

pub async fn submit_init_validator(
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
    }: args::TxInitValidator,
) {
    let alias = tx_args
        .initialized_account_alias
        .as_ref()
        .cloned()
        .unwrap_or_else(|| "validator".to_string());

    let validator_key_alias = format!("{}-key", alias);
    let consensus_key_alias = format!("{}-consensus-key", alias);
    let account_key = ctx.get_opt_cached(&account_key).unwrap_or_else(|| {
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

    let consensus_key = ctx
        .get_opt_cached(&consensus_key)
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

    let protocol_key = ctx.get_opt_cached(&protocol_key);

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

    let validator_vp_code = validator_vp_code_path
        .map(|path| ctx.read_wasm(path))
        .unwrap_or_else(|| ctx.read_wasm(VP_USER_WASM));

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
    let tx_code = ctx.read_wasm(TX_INIT_VALIDATOR_WASM);

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
    let (mut ctx, initialized_accounts) = process_tx(
        ctx,
        &tx_args,
        tx,
        TxSigningKey::WalletAddress(source),
        #[cfg(not(feature = "mainnet"))]
        false,
    )
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

/// Make a ViewingKey that can view notes encrypted by given ExtendedSpendingKey
pub fn to_viewing_key(esk: &ExtendedSpendingKey) -> FullViewingKey {
    ExtendedFullViewingKey::from(esk).fvk
}

/// Generate a valid diversifier, i.e. one that has a diversified base. Return
/// also this diversified base.
pub fn find_valid_diversifier<R: RngCore + CryptoRng>(
    rng: &mut R,
) -> (Diversifier, masp_primitives::jubjub::SubgroupPoint) {
    let mut diversifier;
    let g_d;
    // Keep generating random diversifiers until one has a diversified base
    loop {
        let mut d = [0; 11];
        rng.fill_bytes(&mut d);
        diversifier = Diversifier(d);
        if let Some(val) = diversifier.g_d() {
            g_d = val;
            break;
        }
    }
    (diversifier, g_d)
}

/// Determine if using the current note would actually bring us closer to our
/// target
pub fn is_amount_required(src: Amount, dest: Amount, delta: Amount) -> bool {
    if delta > Amount::zero() {
        let gap = dest - src;
        for (asset_type, value) in gap.components() {
            if *value > 0 && delta[asset_type] > 0 {
                return true;
            }
        }
    }
    false
}

/// An extension of Option's cloned method for pair types
fn cloned_pair<T: Clone, U: Clone>((a, b): (&T, &U)) -> (T, U) {
    (a.clone(), b.clone())
}

/// Errors that can occur when trying to retrieve pinned transaction
#[derive(PartialEq, Eq)]
pub enum PinnedBalanceError {
    /// No transaction has yet been pinned to the given payment address
    NoTransactionPinned,
    /// The supplied viewing key does not recognize payments to given address
    InvalidViewingKey,
}

/// Represents the amount used of different conversions
pub type Conversions =
    HashMap<AssetType, (AllowedConversion, MerklePath<Node>, i64)>;

/// Represents the changes that were made to a list of transparent accounts
pub type TransferDelta = HashMap<Address, Amount<Address>>;

/// Represents the changes that were made to a list of shielded accounts
pub type TransactionDelta = HashMap<ViewingKey, Amount>;

/// Represents the current state of the shielded pool from the perspective of
/// the chosen viewing keys.
#[derive(BorshSerialize, BorshDeserialize, Debug)]
pub struct ShieldedContext {
    /// Location where this shielded context is saved
    #[borsh_skip]
    context_dir: PathBuf,
    /// The last transaction index to be processed in this context
    last_txidx: u64,
    /// The commitment tree produced by scanning all transactions up to tx_pos
    tree: CommitmentTree<Node>,
    /// Maps viewing keys to applicable note positions
    pos_map: HashMap<ViewingKey, HashSet<usize>>,
    /// Maps a nullifier to the note position to which it applies
    nf_map: HashMap<[u8; 32], usize>,
    /// Maps note positions to their corresponding notes
    note_map: HashMap<usize, Note>,
    /// Maps note positions to their corresponding memos
    memo_map: HashMap<usize, Memo>,
    /// Maps note positions to the diversifier of their payment address
    div_map: HashMap<usize, Diversifier>,
    /// Maps note positions to their witness (used to make merkle paths)
    witness_map: HashMap<usize, IncrementalWitness<Node>>,
    /// Tracks what each transaction does to various account balances
    delta_map: BTreeMap<
        (BlockHeight, TxIndex),
        (Epoch, TransferDelta, TransactionDelta),
    >,
    /// The set of note positions that have been spent
    spents: HashSet<usize>,
    /// Maps asset types to their decodings
    asset_types: HashMap<AssetType, (Address, Epoch)>,
    /// Maps note positions to their corresponding viewing keys
    vk_map: HashMap<usize, ViewingKey>,
}

/// Shielded context file name
const FILE_NAME: &str = "shielded.dat";
const TMP_FILE_NAME: &str = "shielded.tmp";

/// Default implementation to ease construction of TxContexts. Derive cannot be
/// used here due to CommitmentTree not implementing Default.
impl Default for ShieldedContext {
    fn default() -> ShieldedContext {
        ShieldedContext {
            context_dir: PathBuf::from(FILE_NAME),
            last_txidx: u64::default(),
            tree: CommitmentTree::empty(),
            pos_map: HashMap::default(),
            nf_map: HashMap::default(),
            note_map: HashMap::default(),
            memo_map: HashMap::default(),
            div_map: HashMap::default(),
            witness_map: HashMap::default(),
            spents: HashSet::default(),
            delta_map: BTreeMap::default(),
            asset_types: HashMap::default(),
            vk_map: HashMap::default(),
        }
    }
}

impl ShieldedContext {
    /// Try to load the last saved shielded context from the given context
    /// directory. If this fails, then leave the current context unchanged.
    pub fn load(&mut self) -> std::io::Result<()> {
        // Try to load shielded context from file
        let mut ctx_file = File::open(self.context_dir.join(FILE_NAME))?;
        let mut bytes = Vec::new();
        ctx_file.read_to_end(&mut bytes)?;
        let mut new_ctx = Self::deserialize(&mut &bytes[..])?;
        // Associate the originating context directory with the
        // shielded context under construction
        new_ctx.context_dir = self.context_dir.clone();
        *self = new_ctx;
        Ok(())
    }

    /// Save this shielded context into its associated context directory
    pub fn save(&self) -> std::io::Result<()> {
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
            self.serialize(&mut bytes)
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

    /// Merge data from the given shielded context into the current shielded
    /// context. It must be the case that the two shielded contexts share the
    /// same last transaction ID and share identical commitment trees.
    pub fn merge(&mut self, new_ctx: ShieldedContext) {
        debug_assert_eq!(self.last_txidx, new_ctx.last_txidx);
        // Merge by simply extending maps. Identical keys should contain
        // identical values, so overwriting should not be problematic.
        self.pos_map.extend(new_ctx.pos_map);
        self.nf_map.extend(new_ctx.nf_map);
        self.note_map.extend(new_ctx.note_map);
        self.memo_map.extend(new_ctx.memo_map);
        self.div_map.extend(new_ctx.div_map);
        self.witness_map.extend(new_ctx.witness_map);
        self.spents.extend(new_ctx.spents);
        self.asset_types.extend(new_ctx.asset_types);
        self.vk_map.extend(new_ctx.vk_map);
        // The deltas are the exception because different keys can reveal
        // different parts of the same transaction. Hence each delta needs to be
        // merged separately.
        for ((height, idx), (ep, ntfer_delta, ntx_delta)) in new_ctx.delta_map {
            let (_ep, tfer_delta, tx_delta) = self
                .delta_map
                .entry((height, idx))
                .or_insert((ep, TransferDelta::new(), TransactionDelta::new()));
            tfer_delta.extend(ntfer_delta);
            tx_delta.extend(ntx_delta);
        }
    }

    /// Fetch the current state of the multi-asset shielded pool into a
    /// ShieldedContext
    pub async fn fetch(
        &mut self,
        ledger_address: &TendermintAddress,
        sks: &[ExtendedSpendingKey],
        fvks: &[ViewingKey],
    ) {
        // First determine which of the keys requested to be fetched are new.
        // Necessary because old transactions will need to be scanned for new
        // keys.
        let mut unknown_keys = Vec::new();
        for esk in sks {
            let vk = to_viewing_key(esk).vk;
            if !self.pos_map.contains_key(&vk) {
                unknown_keys.push(vk);
            }
        }
        for vk in fvks {
            if !self.pos_map.contains_key(vk) {
                unknown_keys.push(*vk);
            }
        }

        // If unknown keys are being used, we need to scan older transactions
        // for any unspent notes
        let (txs, mut tx_iter);
        if !unknown_keys.is_empty() {
            // Load all transactions accepted until this point
            txs = Self::fetch_shielded_transfers(ledger_address, 0).await;
            tx_iter = txs.iter();
            // Do this by constructing a shielding context only for unknown keys
            let mut tx_ctx = ShieldedContext::new(self.context_dir.clone());
            for vk in unknown_keys {
                tx_ctx.pos_map.entry(vk).or_insert_with(HashSet::new);
            }
            // Update this unknown shielded context until it is level with self
            while tx_ctx.last_txidx != self.last_txidx {
                if let Some(((height, idx), (epoch, tx))) = tx_iter.next() {
                    tx_ctx.scan_tx(*height, *idx, *epoch, tx);
                } else {
                    break;
                }
            }
            // Merge the context data originating from the unknown keys into the
            // current context
            self.merge(tx_ctx);
        } else {
            // Load only transactions accepted from last_txid until this point
            txs =
                Self::fetch_shielded_transfers(ledger_address, self.last_txidx)
                    .await;
            tx_iter = txs.iter();
        }
        // Now that we possess the unspent notes corresponding to both old and
        // new keys up until tx_pos, proceed to scan the new transactions.
        for ((height, idx), (epoch, tx)) in &mut tx_iter {
            self.scan_tx(*height, *idx, *epoch, tx);
        }
    }

    /// Initialize a shielded transaction context that identifies notes
    /// decryptable by any viewing key in the given set
    pub fn new(context_dir: PathBuf) -> ShieldedContext {
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
        Self {
            context_dir,
            ..Default::default()
        }
    }

    /// Obtain a chronologically-ordered list of all accepted shielded
    /// transactions from the ledger. The ledger conceptually stores
    /// transactions as a vector. More concretely, the HEAD_TX_KEY location
    /// stores the index of the last accepted transaction and each transaction
    /// is stored at a key derived from its index.
    pub async fn fetch_shielded_transfers(
        ledger_address: &TendermintAddress,
        last_txidx: u64,
    ) -> BTreeMap<(BlockHeight, TxIndex), (Epoch, Transfer)> {
        let client = HttpClient::new(ledger_address.clone()).unwrap();
        // The address of the MASP account
        let masp_addr = masp();
        // Construct the key where last transaction pointer is stored
        let head_tx_key = Key::from(masp_addr.to_db_key())
            .push(&HEAD_TX_KEY.to_owned())
            .expect("Cannot obtain a storage key");
        // Query for the index of the last accepted transaction
        let head_txidx = query_storage_value::<u64>(&client, &head_tx_key)
            .await
            .unwrap_or(0);
        let mut shielded_txs = BTreeMap::new();
        // Fetch all the transactions we do not have yet
        for i in last_txidx..head_txidx {
            // Construct the key for where the current transaction is stored
            let current_tx_key = Key::from(masp_addr.to_db_key())
                .push(&(TX_KEY_PREFIX.to_owned() + &i.to_string()))
                .expect("Cannot obtain a storage key");
            // Obtain the current transaction
            let (tx_epoch, tx_height, tx_index, current_tx) =
                query_storage_value::<(Epoch, BlockHeight, TxIndex, Transfer)>(
                    &client,
                    &current_tx_key,
                )
                .await
                .unwrap();
            // Collect the current transaction
            shielded_txs.insert((tx_height, tx_index), (tx_epoch, current_tx));
        }
        shielded_txs
    }

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
        } else {
            return;
        };
        // For tracking the account changes caused by this Transaction
        let mut transaction_delta = TransactionDelta::new();
        // Listen for notes sent to our viewing keys
        for so in &shielded.shielded_outputs {
            // Create merkle tree leaf node from note commitment
            let node = Node::new(so.cmu.to_repr());
            // Update each merkle tree in the witness map with the latest
            // addition
            for (_, witness) in self.witness_map.iter_mut() {
                witness.append(node).expect("note commitment tree is full");
            }
            let note_pos = self.tree.size();
            self.tree
                .append(node)
                .expect("note commitment tree is full");
            // Finally, make it easier to construct merkle paths to this new
            // note
            let witness = IncrementalWitness::<Node>::from_tree(&self.tree);
            self.witness_map.insert(note_pos, witness);
            // Let's try to see if any of our viewing keys can decrypt latest
            // note
            for (vk, notes) in self.pos_map.iter_mut() {
                let decres = try_sapling_note_decryption::<TestNetwork>(
                    0,
                    &vk.ivk().0,
                    &so.ephemeral_key.into_subgroup().unwrap(),
                    &so.cmu,
                    &so.enc_ciphertext,
                );
                // So this current viewing key does decrypt this current note...
                if let Some((note, pa, memo)) = decres {
                    // Add this note to list of notes decrypted by this viewing
                    // key
                    notes.insert(note_pos);
                    // Compute the nullifier now to quickly recognize when spent
                    let nf = note.nf(vk, note_pos.try_into().unwrap());
                    self.note_map.insert(note_pos, note);
                    self.memo_map.insert(note_pos, memo);
                    // The payment address' diversifier is required to spend
                    // note
                    self.div_map.insert(note_pos, *pa.diversifier());
                    self.nf_map.insert(nf.0, note_pos);
                    // Note the account changes
                    let balance = transaction_delta
                        .entry(*vk)
                        .or_insert_with(Amount::zero);
                    *balance +=
                        Amount::from_nonnegative(note.asset_type, note.value)
                            .expect(
                                "found note with invalid value or asset type",
                            );
                    self.vk_map.insert(note_pos, *vk);
                    break;
                }
            }
        }
        // Cancel out those of our notes that have been spent
        for ss in &shielded.shielded_spends {
            // If the shielded spend's nullifier is in our map, then target note
            // is rendered unusable
            if let Some(note_pos) = self.nf_map.get(&ss.nullifier) {
                self.spents.insert(*note_pos);
                // Note the account changes
                let balance = transaction_delta
                    .entry(self.vk_map[note_pos])
                    .or_insert_with(Amount::zero);
                let note = self.note_map[note_pos];
                *balance -=
                    Amount::from_nonnegative(note.asset_type, note.value)
                        .expect("found note with invalid value or asset type");
            }
        }
        // Record the changes to the transparent accounts
        let transparent_delta =
            Amount::from_nonnegative(tx.token.clone(), u64::from(tx.amount))
                .expect("invalid value for amount");
        let mut transfer_delta = TransferDelta::new();
        transfer_delta
            .insert(tx.source.clone(), Amount::zero() - &transparent_delta);
        transfer_delta.insert(tx.target.clone(), transparent_delta);
        self.delta_map.insert(
            (height, index),
            (epoch, transfer_delta, transaction_delta),
        );
        self.last_txidx += 1;
    }

    /// Summarize the effects on shielded and transparent accounts of each
    /// Transfer in this context
    pub fn get_tx_deltas(
        &self,
    ) -> &BTreeMap<
        (BlockHeight, TxIndex),
        (Epoch, TransferDelta, TransactionDelta),
    > {
        &self.delta_map
    }

    /// Compute the total unspent notes associated with the viewing key in the
    /// context. If the key is not in the context, then we do not know the
    /// balance and hence we return None.
    pub fn compute_shielded_balance(&self, vk: &ViewingKey) -> Option<Amount> {
        // Cannot query the balance of a key that's not in the map
        if !self.pos_map.contains_key(vk) {
            return None;
        }
        let mut val_acc = Amount::zero();
        // Retrieve the notes that can be spent by this key
        if let Some(avail_notes) = self.pos_map.get(vk) {
            for note_idx in avail_notes {
                // Spent notes cannot contribute a new transaction's pool
                if self.spents.contains(note_idx) {
                    continue;
                }
                // Get note associated with this ID
                let note = self.note_map.get(note_idx).unwrap();
                // Finally add value to multi-asset accumulator
                val_acc +=
                    Amount::from_nonnegative(note.asset_type, note.value)
                        .expect("found note with invalid value or asset type");
            }
        }
        Some(val_acc)
    }

    /// Query the ledger for the decoding of the given asset type and cache it
    /// if it is found.
    pub async fn decode_asset_type(
        &mut self,
        client: HttpClient,
        asset_type: AssetType,
    ) -> Option<(Address, Epoch)> {
        // Try to find the decoding in the cache
        if let decoded @ Some(_) = self.asset_types.get(&asset_type) {
            return decoded.cloned();
        }
        // Query for the ID of the last accepted transaction
        let (addr, ep, _conv, _path): (Address, _, Amount, MerklePath<Node>) =
            query_conversion(client, asset_type).await?;
        self.asset_types.insert(asset_type, (addr.clone(), ep));
        Some((addr, ep))
    }

    /// Query the ledger for the conversion that is allowed for the given asset
    /// type and cache it.
    async fn query_allowed_conversion<'a>(
        &'a mut self,
        client: HttpClient,
        asset_type: AssetType,
        conversions: &'a mut Conversions,
    ) -> Option<&'a mut (AllowedConversion, MerklePath<Node>, i64)> {
        match conversions.entry(asset_type) {
            Entry::Occupied(conv_entry) => Some(conv_entry.into_mut()),
            Entry::Vacant(conv_entry) => {
                // Query for the ID of the last accepted transaction
                let (addr, ep, conv, path): (Address, _, _, _) =
                    query_conversion(client, asset_type).await?;
                self.asset_types.insert(asset_type, (addr, ep));
                // If the conversion is 0, then we just have a pure decoding
                if conv == Amount::zero() {
                    None
                } else {
                    Some(conv_entry.insert((Amount::into(conv), path, 0)))
                }
            }
        }
    }

    /// Compute the total unspent notes associated with the viewing key in the
    /// context and express that value in terms of the currently timestamped
    /// asset types. If the key is not in the context, then we do not know the
    /// balance and hence we return None.
    pub async fn compute_exchanged_balance(
        &mut self,
        client: HttpClient,
        vk: &ViewingKey,
        target_epoch: Epoch,
    ) -> Option<Amount> {
        // First get the unexchanged balance
        if let Some(balance) = self.compute_shielded_balance(vk) {
            // And then exchange balance into current asset types
            Some(
                self.compute_exchanged_amount(
                    client,
                    balance,
                    target_epoch,
                    HashMap::new(),
                )
                .await
                .0,
            )
        } else {
            None
        }
    }

    /// Try to convert as much of the given asset type-value pair using the
    /// given allowed conversion. usage is incremented by the amount of the
    /// conversion used, the conversions are applied to the given input, and
    /// the trace amount that could not be converted is moved from input to
    /// output.
    fn apply_conversion(
        conv: AllowedConversion,
        asset_type: AssetType,
        value: i64,
        usage: &mut i64,
        input: &mut Amount,
        output: &mut Amount,
    ) {
        // If conversion if possible, accumulate the exchanged amount
        let conv: Amount = conv.into();
        // The amount required of current asset to qualify for conversion
        let threshold = -conv[&asset_type];
        if threshold == 0 {
            eprintln!(
                "Asset threshold of selected conversion for asset type {} is \
                 0, this is a bug, please report it.",
                asset_type
            );
        }
        // We should use an amount of the AllowedConversion that almost
        // cancels the original amount
        let required = value / threshold;
        // Forget about the trace amount left over because we cannot
        // realize its value
        let trace = Amount::from_pair(asset_type, value % threshold).unwrap();
        // Record how much more of the given conversion has been used
        *usage += required;
        // Apply the conversions to input and move the trace amount to output
        *input += conv * required - &trace;
        *output += trace;
    }

    /// Convert the given amount into the latest asset types whilst making a
    /// note of the conversions that were used. Note that this function does
    /// not assume that allowed conversions from the ledger are expressed in
    /// terms of the latest asset types.
    pub async fn compute_exchanged_amount(
        &mut self,
        client: HttpClient,
        mut input: Amount,
        target_epoch: Epoch,
        mut conversions: Conversions,
    ) -> (Amount, Conversions) {
        // Where we will store our exchanged value
        let mut output = Amount::zero();
        // Repeatedly exchange assets until it is no longer possible
        while let Some((asset_type, value)) =
            input.components().next().map(cloned_pair)
        {
            let target_asset_type = self
                .decode_asset_type(client.clone(), asset_type)
                .await
                .map(|(addr, _epoch)| make_asset_type(target_epoch, &addr))
                .unwrap_or(asset_type);
            let at_target_asset_type = asset_type == target_asset_type;
            if let (Some((conv, _wit, usage)), false) = (
                self.query_allowed_conversion(
                    client.clone(),
                    asset_type,
                    &mut conversions,
                )
                .await,
                at_target_asset_type,
            ) {
                println!(
                    "converting current asset type to latest asset type..."
                );
                // Not at the target asset type, not at the latest asset type.
                // Apply conversion to get from current asset type to the latest
                // asset type.
                Self::apply_conversion(
                    conv.clone(),
                    asset_type,
                    value,
                    usage,
                    &mut input,
                    &mut output,
                );
            } else if let (Some((conv, _wit, usage)), false) = (
                self.query_allowed_conversion(
                    client.clone(),
                    target_asset_type,
                    &mut conversions,
                )
                .await,
                at_target_asset_type,
            ) {
                println!(
                    "converting latest asset type to target asset type..."
                );
                // Not at the target asset type, yes at the latest asset type.
                // Apply inverse conversion to get from latest asset type to
                // the target asset type.
                Self::apply_conversion(
                    conv.clone(),
                    asset_type,
                    value,
                    usage,
                    &mut input,
                    &mut output,
                );
            } else {
                // At the target asset type. Then move component over to output.
                let comp = input.project(asset_type);
                output += &comp;
                // Strike from input to avoid repeating computation
                input -= comp;
            }
        }
        (output, conversions)
    }

    /// Collect enough unspent notes in this context to exceed the given amount
    /// of the specified asset type. Return the total value accumulated plus
    /// notes and the corresponding diversifiers/merkle paths that were used to
    /// achieve the total value.
    pub async fn collect_unspent_notes(
        &mut self,
        ledger_address: TendermintAddress,
        vk: &ViewingKey,
        target: Amount,
        target_epoch: Epoch,
    ) -> (
        Amount,
        Vec<(Diversifier, Note, MerklePath<Node>)>,
        Conversions,
    ) {
        // Establish connection with which to do exchange rate queries
        let client = HttpClient::new(ledger_address.clone()).unwrap();
        let mut conversions = HashMap::new();
        let mut val_acc = Amount::zero();
        let mut notes = Vec::new();
        // Retrieve the notes that can be spent by this key
        if let Some(avail_notes) = self.pos_map.get(vk).cloned() {
            for note_idx in &avail_notes {
                // No more transaction inputs are required once we have met
                // the target amount
                if val_acc >= target {
                    break;
                }
                // Spent notes cannot contribute a new transaction's pool
                if self.spents.contains(note_idx) {
                    continue;
                }
                // Get note, merkle path, diversifier associated with this ID
                let note = *self.note_map.get(note_idx).unwrap();

                // The amount contributed by this note before conversion
                let pre_contr = Amount::from_pair(note.asset_type, note.value)
                    .expect("received note has invalid value or asset type");
                let (contr, proposed_convs) = self
                    .compute_exchanged_amount(
                        client.clone(),
                        pre_contr,
                        target_epoch,
                        conversions.clone(),
                    )
                    .await;

                // Use this note only if it brings us closer to our target
                if is_amount_required(
                    val_acc.clone(),
                    target.clone(),
                    contr.clone(),
                ) {
                    // Be sure to record the conversions used in computing
                    // accumulated value
                    val_acc += contr;
                    // Commit the conversions that were used to exchange
                    conversions = proposed_convs;
                    let merkle_path =
                        self.witness_map.get(note_idx).unwrap().path().unwrap();
                    let diversifier = self.div_map.get(note_idx).unwrap();
                    // Commit this note to our transaction
                    notes.push((*diversifier, note, merkle_path));
                }
            }
        }
        (val_acc, notes, conversions)
    }

    /// Compute the combined value of the output notes of the transaction pinned
    /// at the given payment address. This computation uses the supplied viewing
    /// keys to try to decrypt the output notes. If no transaction is pinned at
    /// the given payment address fails with
    /// `PinnedBalanceError::NoTransactionPinned`.
    pub async fn compute_pinned_balance(
        ledger_address: &TendermintAddress,
        owner: PaymentAddress,
        viewing_key: &ViewingKey,
    ) -> Result<(Amount, Epoch), PinnedBalanceError> {
        // Check that the supplied viewing key corresponds to given payment
        // address
        let counter_owner = viewing_key.to_payment_address(
            *masp_primitives::primitives::PaymentAddress::diversifier(
                &owner.into(),
            ),
        );
        match counter_owner {
            Some(counter_owner) if counter_owner == owner.into() => {}
            _ => return Err(PinnedBalanceError::InvalidViewingKey),
        }
        let client = HttpClient::new(ledger_address.clone()).unwrap();
        // The address of the MASP account
        let masp_addr = masp();
        // Construct the key for where the transaction ID would be stored
        let pin_key = Key::from(masp_addr.to_db_key())
            .push(&(PIN_KEY_PREFIX.to_owned() + &owner.hash()))
            .expect("Cannot obtain a storage key");
        // Obtain the transaction pointer at the key
        let txidx = query_storage_value::<u64>(&client, &pin_key)
            .await
            .ok_or(PinnedBalanceError::NoTransactionPinned)?;
        // Construct the key for where the pinned transaction is stored
        let tx_key = Key::from(masp_addr.to_db_key())
            .push(&(TX_KEY_PREFIX.to_owned() + &txidx.to_string()))
            .expect("Cannot obtain a storage key");
        // Obtain the pointed to transaction
        let (tx_epoch, _tx_height, _tx_index, tx) =
            query_storage_value::<(Epoch, BlockHeight, TxIndex, Transfer)>(
                &client, &tx_key,
            )
            .await
            .expect("Ill-formed epoch, transaction pair");
        // Accumulate the combined output note value into this Amount
        let mut val_acc = Amount::zero();
        let tx = tx
            .shielded
            .expect("Pinned Transfers should have shielded part");
        for so in &tx.shielded_outputs {
            // Let's try to see if our viewing key can decrypt current note
            let decres = try_sapling_note_decryption::<TestNetwork>(
                0,
                &viewing_key.ivk().0,
                &so.ephemeral_key.into_subgroup().unwrap(),
                &so.cmu,
                &so.enc_ciphertext,
            );
            match decres {
                // So the given viewing key does decrypt this current note...
                Some((note, pa, _memo)) if pa == owner.into() => {
                    val_acc +=
                        Amount::from_nonnegative(note.asset_type, note.value)
                            .expect(
                                "found note with invalid value or asset type",
                            );
                    break;
                }
                _ => {}
            }
        }
        Ok((val_acc, tx_epoch))
    }

    /// Compute the combined value of the output notes of the pinned transaction
    /// at the given payment address if there's any. The asset types may be from
    /// the epoch of the transaction or even before, so exchange all these
    /// amounts to the epoch of the transaction in order to get the value that
    /// would have been displayed in the epoch of the transaction.
    pub async fn compute_exchanged_pinned_balance(
        &mut self,
        ledger_address: &TendermintAddress,
        owner: PaymentAddress,
        viewing_key: &ViewingKey,
    ) -> Result<(Amount, Epoch), PinnedBalanceError> {
        // Obtain the balance that will be exchanged
        let (amt, ep) =
            Self::compute_pinned_balance(ledger_address, owner, viewing_key)
                .await?;
        // Establish connection with which to do exchange rate queries
        let client = HttpClient::new(ledger_address.clone()).unwrap();
        // Finally, exchange the balance to the transaction's epoch
        Ok((
            self.compute_exchanged_amount(client, amt, ep, HashMap::new())
                .await
                .0,
            ep,
        ))
    }

    /// Convert an amount whose units are AssetTypes to one whose units are
    /// Addresses that they decode to. All asset types not corresponding to
    /// the given epoch are ignored.
    pub async fn decode_amount(
        &mut self,
        client: HttpClient,
        amt: Amount,
        target_epoch: Epoch,
    ) -> Amount<Address> {
        let mut res = Amount::zero();
        for (asset_type, val) in amt.components() {
            // Decode the asset type
            let decoded =
                self.decode_asset_type(client.clone(), *asset_type).await;
            // Only assets with the target timestamp count
            match decoded {
                Some((addr, epoch)) if epoch == target_epoch => {
                    res += &Amount::from_pair(addr, *val).unwrap()
                }
                _ => {}
            }
        }
        res
    }

    /// Convert an amount whose units are AssetTypes to one whose units are
    /// Addresses that they decode to.
    pub async fn decode_all_amounts(
        &mut self,
        client: HttpClient,
        amt: Amount,
    ) -> Amount<(Address, Epoch)> {
        let mut res = Amount::zero();
        for (asset_type, val) in amt.components() {
            // Decode the asset type
            let decoded =
                self.decode_asset_type(client.clone(), *asset_type).await;
            // Only assets with the target timestamp count
            if let Some((addr, epoch)) = decoded {
                res += &Amount::from_pair((addr, epoch), *val).unwrap()
            }
        }
        res
    }
}

/// Make asset type corresponding to given address and epoch
fn make_asset_type(epoch: Epoch, token: &Address) -> AssetType {
    // Typestamp the chosen token with the current epoch
    let token_bytes = (token, epoch.0)
        .try_to_vec()
        .expect("token should serialize");
    // Generate the unique asset identifier from the unique token address
    AssetType::new(token_bytes.as_ref()).expect("unable to create asset type")
}

/// Convert Namada amount and token type to MASP equivalents
fn convert_amount(
    epoch: Epoch,
    token: &Address,
    val: token::Amount,
) -> (AssetType, Amount) {
    let asset_type = make_asset_type(epoch, token);
    // Combine the value and unit into one amount
    let amount = Amount::from_nonnegative(asset_type, u64::from(val))
        .expect("invalid value for amount");
    (asset_type, amount)
}

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
    let file = File::open(&args.proposal_data).expect("File must exist.");
    let proposal: Proposal =
        serde_json::from_reader(file).expect("JSON was not well-formatted");

    let client = HttpClient::new(args.tx.ledger_address.clone()).unwrap();

    let signer = WalletAddress::new(proposal.clone().author.to_string());
    let governance_parameters = rpc::get_governance_parameters(&client).await;
    let current_epoch = rpc::query_and_print_epoch(args::Query {
        ledger_address: args.tx.ledger_address.clone(),
    })
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
            &mut ctx.wallet,
            &signer,
            args.tx.ledger_address.clone(),
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
        let tx_data: Result<InitProposalData, _> = proposal.clone().try_into();
        let init_proposal_data = if let Ok(data) = tx_data {
            data
        } else {
            eprintln!("Invalid data for init proposal transaction.");
            safe_exit(1)
        };

        let balance = rpc::get_token_balance(
            &client,
            &ctx.native_token,
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
        let tx_code = ctx.read_wasm(TX_INIT_PROPOSAL);
        let tx = Tx::new(tx_code, Some(data));

        process_tx(
            ctx,
            &args.tx,
            tx,
            TxSigningKey::WalletAddress(signer),
            #[cfg(not(feature = "mainnet"))]
            false,
        )
        .await;
    }
}

pub async fn submit_vote_proposal(mut ctx: Context, args: args::VoteProposal) {
    let signer = if let Some(addr) = &args.tx.signer {
        addr
    } else {
        eprintln!("Missing mandatory argument --signer.");
        safe_exit(1)
    };

    if args.offline {
        let signer = ctx.get(signer);
        let proposal_file_path =
            args.proposal_data.expect("Proposal file should exist.");
        let file = File::open(&proposal_file_path).expect("File must exist.");

        let proposal: OfflineProposal =
            serde_json::from_reader(file).expect("JSON was not well-formatted");
        let public_key = rpc::get_public_key(
            &proposal.address,
            args.tx.ledger_address.clone(),
        )
        .await
        .expect("Public key should exist.");
        if !proposal.check_signature(&public_key) {
            eprintln!("Proposal signature mismatch!");
            safe_exit(1)
        }

        let signing_key = find_keypair(
            &mut ctx.wallet,
            &signer,
            args.tx.ledger_address.clone(),
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
        let client = HttpClient::new(args.tx.ledger_address.clone()).unwrap();
        let current_epoch = rpc::query_and_print_epoch(args::Query {
            ledger_address: args.tx.ledger_address.clone(),
        })
        .await;

        let voter_address = ctx.get(signer);
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
                        args.tx.ledger_address.clone(),
                        &client,
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
                let tx_code = ctx.read_wasm(TX_VOTE_PROPOSAL);
                let tx = Tx::new(tx_code, Some(data));

                process_tx(
                    ctx,
                    &args.tx,
                    tx,
                    TxSigningKey::WalletAddress(signer.clone()),
                    #[cfg(not(feature = "mainnet"))]
                    false,
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

pub async fn submit_reveal_pk(mut ctx: Context, args: args::RevealPk) {
    let args::RevealPk {
        tx: args,
        public_key,
    } = args;
    let public_key = ctx.get_cached(&public_key);
    if !reveal_pk_if_needed(&mut ctx, &public_key, &args).await {
        let addr: Address = (&public_key).into();
        println!("PK for {addr} is already revealed, nothing to do.");
    }
}

pub async fn reveal_pk_if_needed(
    ctx: &mut Context,
    public_key: &common::PublicKey,
    args: &args::Tx,
) -> bool {
    let addr: Address = public_key.into();
    // Check if PK revealed
    if args.force || !has_revealed_pk(&addr, args.ledger_address.clone()).await
    {
        // If not, submit it
        submit_reveal_pk_aux(ctx, public_key, args).await;
        true
    } else {
        false
    }
}

pub async fn has_revealed_pk(
    addr: &Address,
    ledger_address: TendermintAddress,
) -> bool {
    rpc::get_public_key(addr, ledger_address).await.is_some()
}

pub async fn submit_reveal_pk_aux(
    ctx: &mut Context,
    public_key: &common::PublicKey,
    args: &args::Tx,
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
    let epoch = rpc::query_and_print_epoch(args::Query {
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
}

/// Check if current epoch is in the last third of the voting period of the
/// proposal. This ensures that it is safe to optimize the vote writing to
/// storage.
async fn is_safe_voting_window(
    ledger_address: TendermintAddress,
    client: &HttpClient,
    proposal_id: u64,
    proposal_start_epoch: Epoch,
) -> bool {
    let current_epoch =
        rpc::query_and_print_epoch(args::Query { ledger_address }).await;

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

pub async fn submit_bond(ctx: Context, args: args::Bond) {
    let validator = ctx.get(&args.validator);

    // Check that the validator address exists on chain
    let client = HttpClient::new(args.tx.ledger_address.clone()).unwrap();
    let is_validator = rpc::is_validator(&client, &validator).await;
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
    match rpc::query_storage_value::<token::Amount>(&client, &balance_key).await
    {
        Some(balance) => {
            println!("Found source balance {}", balance);
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
    println!("Wasm tx bond code bytes length = {}\n", tx_code.len());
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
}

pub async fn submit_unbond(ctx: Context, args: args::Unbond) {
    let validator = ctx.get(&args.validator);
    let source = ctx.get_opt(&args.source);

    // Check that the validator address exists on chain
    let client = HttpClient::new(args.tx.ledger_address.clone()).unwrap();
    let is_validator = rpc::is_validator(&client, &validator).await;
    if !is_validator {
        eprintln!(
            "The address {} doesn't belong to any known validator account.",
            validator
        );
        if !args.tx.force {
            safe_exit(1)
        }
    }

    // Check the source's current bond amount
    let bond_source = source.clone().unwrap_or_else(|| validator.clone());
    let bond_amount =
        rpc::query_bond(&client, &bond_source, &validator, None).await;
    println!("BOND AMOUNT REMAINING IS {}", bond_amount);

    if args.amount > bond_amount {
        eprintln!(
            "The total bonds of the source {} is lower than the amount to be \
             unbonded. Amount to unbond is {} and the total bonds is {}.",
            bond_source, args.amount, bond_amount
        );
        if !args.tx.force {
            safe_exit(1)
        }
    }

    let data = pos::Unbond {
        validator: validator.clone(),
        amount: args.amount,
        source: Some(bond_source.clone()),
    };
    let data = data.try_to_vec().expect("Encoding tx data shouldn't fail");

    let tx_code = ctx.read_wasm(TX_UNBOND_WASM);
    let tx = Tx::new(tx_code, Some(data));
    let default_signer = args.source.unwrap_or(args.validator);
    let (_ctx, _) = process_tx(
        ctx,
        &args.tx,
        tx,
        TxSigningKey::WalletAddress(default_signer),
        #[cfg(not(feature = "mainnet"))]
        false,
    )
    .await;

    rpc::query_and_print_unbonds(&client, &bond_source, &validator).await;
}

pub async fn submit_withdraw(ctx: Context, args: args::Withdraw) {
    let validator = ctx.get(&args.validator);
    let source = ctx.get_opt(&args.source);

    let epoch = rpc::query_and_print_epoch(args::Query {
        ledger_address: args.tx.ledger_address.clone(),
    })
    .await;

    // Check that the validator address exists on chain
    let client = HttpClient::new(args.tx.ledger_address.clone()).unwrap();
    let is_validator = rpc::is_validator(&client, &validator).await;
    if !is_validator {
        eprintln!(
            "The address {} doesn't belong to any known validator account.",
            validator
        );
        if !args.tx.force {
            safe_exit(1)
        }
    }

    // Check the source's current unbond amount
    let bond_source = source.clone().unwrap_or_else(|| validator.clone());
    let tokens = rpc::query_withdrawable_tokens(
        &client,
        &bond_source,
        &validator,
        Some(epoch),
    )
    .await;
    if tokens == 0.into() {
        eprintln!(
            "There are no unbonded bonds ready to withdraw in the current \
             epoch {}.",
            epoch
        );
        rpc::query_and_print_unbonds(&client, &bond_source, &validator).await;
        if !args.tx.force {
            safe_exit(1)
        }
    } else {
        println!("Found {tokens} tokens that can be withdrawn.");
        println!("Submitting transaction to withdraw them...");
    }

    let data = pos::Withdraw { validator, source };
    let data = data.try_to_vec().expect("Encoding tx data shouldn't fail");

    let tx_code = ctx.read_wasm(TX_WITHDRAW_WASM);
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
}

pub async fn submit_validator_commission_change(
    ctx: Context,
    args: args::TxCommissionRateChange,
) {
    let epoch = rpc::query_and_print_epoch(args::Query {
        ledger_address: args.tx.ledger_address.clone(),
    })
    .await;

    let tx_code = ctx.read_wasm(TX_CHANGE_COMMISSION_WASM);
    let client = HttpClient::new(args.tx.ledger_address.clone()).unwrap();

    // TODO: put following two let statements in its own function
    let params_key = namada::ledger::pos::params_key();
    let params = query_storage_value::<PosParams>(&client, &params_key)
        .await
        .expect("Parameter should be defined.");

    let validator = ctx.get(&args.validator);
    if rpc::is_validator(&client, &validator).await {
        if args.rate < Decimal::ZERO || args.rate > Decimal::ONE {
            eprintln!("Invalid new commission rate, received {}", args.rate);
            if !args.tx.force {
                safe_exit(1)
            }
        }

        let pipeline_epoch_minus_one = epoch + params.pipeline_len - 1;

        match rpc::query_commission_rate(
            &client,
            &validator,
            Some(pipeline_epoch_minus_one),
        )
        .await
        {
            Some(CommissionPair {
                commission_rate,
                max_commission_change_per_epoch,
            }) => {
                if (args.rate - commission_rate).abs()
                    > max_commission_change_per_epoch
                {
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
            None => {
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
}

/// Submit transaction and wait for result. Returns a list of addresses
/// initialized in the transaction if any. In dry run, this is always empty.
async fn process_tx(
    ctx: Context,
    args: &args::Tx,
    tx: Tx,
    default_signer: TxSigningKey,
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
}

/// Save accounts initialized from a tx into the wallet, if any.
async fn save_initialized_accounts(
    mut ctx: Context,
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
        let wallet = &mut ctx.wallet;
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
    address: TendermintAddress,
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
        tendermint_rpc_address = ?address,
        transaction = ?to_broadcast,
        "Broadcasting transaction",
    );
    let rpc_cli = HttpClient::new(address)?;

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
    address: TendermintAddress,
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
    broadcast_tx(address.clone(), &to_broadcast).await?;

    let max_wait_time = Duration::from_secs(
        env::var(ENV_VAR_NAMADA_EVENTS_MAX_WAIT_TIME_SECONDS)
            .ok()
            .and_then(|val| val.parse().ok())
            .unwrap_or(DEFAULT_NAMADA_EVENTS_MAX_WAIT_TIME_SECONDS),
    );
    let deadline = Instant::now() + max_wait_time;

    tracing::debug!(
        tendermint_rpc_address = ?address,
        transaction = ?to_broadcast,
        ?deadline,
        "Awaiting transaction approval",
    );

    let parsed = {
        let wrapper_query = rpc::TxEventQuery::Accepted(wrapper_hash.as_str());
        let event =
            rpc::query_tx_status(wrapper_query, address.clone(), deadline)
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
                rpc::query_tx_status(decrypted_query, address, deadline).await;
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
