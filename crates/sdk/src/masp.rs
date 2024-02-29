//! MASP verification wrappers.

use std::cmp::Ordering;
use std::collections::{btree_map, BTreeMap, BTreeSet, HashMap, HashSet};
use std::env;
use std::fmt::Debug;
use std::ops::Deref;
use std::path::PathBuf;
use std::str::FromStr;

use borsh::{BorshDeserialize, BorshSerialize};
use borsh_ext::BorshSerializeExt;
use itertools::Either;
use lazy_static::lazy_static;
use masp_primitives::asset_type::AssetType;
#[cfg(feature = "mainnet")]
use masp_primitives::consensus::MainNetwork;
#[cfg(not(feature = "mainnet"))]
use masp_primitives::consensus::TestNetwork;
use masp_primitives::convert::AllowedConversion;
use masp_primitives::ff::PrimeField;
use masp_primitives::group::GroupEncoding;
use masp_primitives::memo::MemoBytes;
use masp_primitives::merkle_tree::{
    CommitmentTree, IncrementalWitness, MerklePath,
};
use masp_primitives::sapling::keys::FullViewingKey;
use masp_primitives::sapling::note_encryption::*;
use masp_primitives::sapling::redjubjub::PublicKey;
use masp_primitives::sapling::{
    Diversifier, Node, Note, Nullifier, ViewingKey,
};
use masp_primitives::transaction::builder::{self, *};
use masp_primitives::transaction::components::sapling::builder::SaplingMetadata;
use masp_primitives::transaction::components::transparent::builder::TransparentBuilder;
use masp_primitives::transaction::components::{
    ConvertDescription, I128Sum, OutputDescription, SpendDescription, TxOut,
    U64Sum, ValueSum,
};
use masp_primitives::transaction::fees::fixed::FeeRule;
use masp_primitives::transaction::sighash::{signature_hash, SignableInput};
use masp_primitives::transaction::txid::TxIdDigester;
use masp_primitives::transaction::{
    Authorization, Authorized, Transaction, TransactionData,
    TransparentAddress, Unauthorized,
};
use masp_primitives::zip32::{ExtendedFullViewingKey, ExtendedSpendingKey};
use masp_proofs::bellman::groth16::PreparedVerifyingKey;
use masp_proofs::bls12_381::Bls12;
use masp_proofs::prover::LocalTxProver;
#[cfg(not(feature = "testing"))]
use masp_proofs::sapling::SaplingVerificationContext;
use namada_core::address::{Address, MASP};
use namada_core::dec::Dec;
pub use namada_core::masp::{
    encode_asset_type, AssetData, BalanceOwner, ExtendedViewingKey,
    PaymentAddress, TransferSource, TransferTarget,
};
use namada_core::storage::{BlockHeight, Epoch, IndexedTx, TxIndex};
use namada_core::time::{DateTimeUtc, DurationSecs};
use namada_core::uint::Uint;
use namada_ibc::IbcMessage;
use namada_token::{self as token, Denomination, MaspDigitPos, Transfer};
use namada_tx::data::{TxResult, WrapperTx};
use namada_tx::Tx;
use rand_core::{CryptoRng, OsRng, RngCore};
use ripemd::Digest as RipemdDigest;
use sha2::Digest;
use thiserror::Error;
use token::storage_key::{balance_key, is_any_shielded_action_balance_key};
use token::Amount;

use crate::error::{Error, PinnedBalanceError, QueryError};
use crate::io::Io;
use crate::queries::Client;
use crate::rpc::{
    query_block, query_conversion, query_denom, query_epoch_at_height,
    query_native_token,
};
use crate::tendermint_rpc::query::Query;
use crate::tendermint_rpc::Order;
use crate::{display_line, edisplay_line, rpc, MaybeSend, MaybeSync, Namada};

/// Env var to point to a dir with MASP parameters. When not specified,
/// the default OS specific path is used.
pub const ENV_VAR_MASP_PARAMS_DIR: &str = "NAMADA_MASP_PARAMS_DIR";

/// Randomness seed for MASP integration tests to build proofs with
/// deterministic rng.
pub const ENV_VAR_MASP_TEST_SEED: &str = "NAMADA_MASP_TEST_SEED";

/// The network to use for MASP
#[cfg(feature = "mainnet")]
const NETWORK: MainNetwork = MainNetwork;
#[cfg(not(feature = "mainnet"))]
const NETWORK: TestNetwork = TestNetwork;

// TODO these could be exported from masp_proof crate
/// Spend circuit name
pub const SPEND_NAME: &str = "masp-spend.params";
/// Output circuit name
pub const OUTPUT_NAME: &str = "masp-output.params";
/// Convert circuit name
pub const CONVERT_NAME: &str = "masp-convert.params";

/// Type alias for convenience and profit
pub type IndexedNoteData = BTreeMap<
    IndexedTx,
    (Epoch, BTreeSet<namada_core::storage::Key>, Transaction),
>;

/// Type alias for the entries of [`IndexedNoteData`] iterators
pub type IndexedNoteEntry = (
    IndexedTx,
    (Epoch, BTreeSet<namada_core::storage::Key>, Transaction),
);

/// Shielded transfer
#[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
pub struct ShieldedTransfer {
    /// Shielded transfer builder
    pub builder: Builder<(), (), ExtendedFullViewingKey, ()>,
    /// MASP transaction
    pub masp_tx: Transaction,
    /// Metadata
    pub metadata: SaplingMetadata,
    /// Epoch in which the transaction was created
    pub epoch: Epoch,
}

/// Shielded pool data for a token
#[derive(BorshSerialize, BorshDeserialize)]
pub struct MaspTokenRewardData {
    pub name: String,
    pub address: Address,
    pub max_reward_rate: Dec,
    pub kp_gain: Dec,
    pub kd_gain: Dec,
    pub locked_amount_target: Uint,
}

/// A return type for gen_shielded_transfer
#[derive(Error, Debug)]
pub enum TransferErr {
    /// Build error for masp errors
    #[error("{0}")]
    Build(#[from] builder::Error<std::convert::Infallible>),
    /// errors
    #[error("{0}")]
    General(#[from] Error),
}

/// MASP verifying keys
pub struct PVKs {
    /// spend verifying key
    spend_vk: PreparedVerifyingKey<Bls12>,
    /// convert verifying key
    convert_vk: PreparedVerifyingKey<Bls12>,
    /// output verifying key
    output_vk: PreparedVerifyingKey<Bls12>,
}

lazy_static! {
    /// MASP verifying keys load from parameters
    static ref VERIFIYING_KEYS: PVKs =
        {
        let params_dir = get_params_dir();
        let [spend_path, convert_path, output_path] =
            [SPEND_NAME, CONVERT_NAME, OUTPUT_NAME].map(|p| params_dir.join(p));

        #[cfg(feature = "download-params")]
        if !spend_path.exists() || !convert_path.exists() || !output_path.exists() {
            let paths = masp_proofs::download_masp_parameters(None).expect(
                "MASP parameters were not present, expected the download to \
                succeed",
            );
            if paths.spend != spend_path
                || paths.convert != convert_path
                || paths.output != output_path
            {
                panic!(
                    "unrecoverable: downloaded missing masp params, but to an \
                    unfamiliar path"
                )
            }
        }
        // size and blake2b checked here
        let params = masp_proofs::load_parameters(
            spend_path.as_path(),
            output_path.as_path(),
            convert_path.as_path(),
        );
        PVKs {
            spend_vk: params.spend_vk,
            convert_vk: params.convert_vk,
            output_vk: params.output_vk
        }
    };
}

/// Make sure the MASP params are present and load verifying keys into memory
pub fn preload_verifying_keys() -> &'static PVKs {
    &VERIFIYING_KEYS
}

fn load_pvks() -> &'static PVKs {
    &VERIFIYING_KEYS
}

/// check_spend wrapper
pub fn check_spend(
    spend: &SpendDescription<<Authorized as Authorization>::SaplingAuth>,
    sighash: &[u8; 32],
    #[cfg(not(feature = "testing"))] ctx: &mut SaplingVerificationContext,
    #[cfg(feature = "testing")]
    ctx: &mut testing::MockSaplingVerificationContext,
    parameters: &PreparedVerifyingKey<Bls12>,
) -> bool {
    let zkproof =
        masp_proofs::bellman::groth16::Proof::read(spend.zkproof.as_slice());
    let zkproof = match zkproof {
        Ok(zkproof) => zkproof,
        _ => return false,
    };

    ctx.check_spend(
        spend.cv,
        spend.anchor,
        &spend.nullifier.0,
        PublicKey(spend.rk.0),
        sighash,
        spend.spend_auth_sig,
        zkproof,
        parameters,
    )
}

/// check_output wrapper
pub fn check_output(
    output: &OutputDescription<<<Authorized as Authorization>::SaplingAuth as masp_primitives::transaction::components::sapling::Authorization>::Proof>,
    #[cfg(not(feature = "testing"))] ctx: &mut SaplingVerificationContext,
    #[cfg(feature = "testing")]
    ctx: &mut testing::MockSaplingVerificationContext,
    parameters: &PreparedVerifyingKey<Bls12>,
) -> bool {
    let zkproof =
        masp_proofs::bellman::groth16::Proof::read(output.zkproof.as_slice());
    let zkproof = match zkproof {
        Ok(zkproof) => zkproof,
        _ => return false,
    };
    let epk =
        masp_proofs::jubjub::ExtendedPoint::from_bytes(&output.ephemeral_key.0);
    let epk = match epk.into() {
        Some(p) => p,
        None => return false,
    };

    ctx.check_output(output.cv, output.cmu, epk, zkproof, parameters)
}

/// check convert wrapper
pub fn check_convert(
    convert: &ConvertDescription<<<Authorized as Authorization>::SaplingAuth as masp_primitives::transaction::components::sapling::Authorization>::Proof>,
    #[cfg(not(feature = "testing"))] ctx: &mut SaplingVerificationContext,
    #[cfg(feature = "testing")]
    ctx: &mut testing::MockSaplingVerificationContext,
    parameters: &PreparedVerifyingKey<Bls12>,
) -> bool {
    let zkproof =
        masp_proofs::bellman::groth16::Proof::read(convert.zkproof.as_slice());
    let zkproof = match zkproof {
        Ok(zkproof) => zkproof,
        _ => return false,
    };

    ctx.check_convert(convert.cv, convert.anchor, zkproof, parameters)
}

/// Represents an authorization where the Sapling bundle is authorized and the
/// transparent bundle is unauthorized.
pub struct PartialAuthorized;

impl Authorization for PartialAuthorized {
    type SaplingAuth = <Authorized as Authorization>::SaplingAuth;
    type TransparentAuth = <Unauthorized as Authorization>::TransparentAuth;
}

/// Partially deauthorize the transparent bundle
fn partial_deauthorize(
    tx_data: &TransactionData<Authorized>,
) -> Option<TransactionData<PartialAuthorized>> {
    let transp = tx_data.transparent_bundle().and_then(|x| {
        let mut tb = TransparentBuilder::empty();
        for vin in &x.vin {
            tb.add_input(TxOut {
                asset_type: vin.asset_type,
                value: vin.value,
                address: vin.address,
            })
            .ok()?;
        }
        for vout in &x.vout {
            tb.add_output(&vout.address, vout.asset_type, vout.value)
                .ok()?;
        }
        tb.build()
    });
    if tx_data.transparent_bundle().is_some() != transp.is_some() {
        return None;
    }
    Some(TransactionData::from_parts(
        tx_data.version(),
        tx_data.consensus_branch_id(),
        tx_data.lock_time(),
        tx_data.expiry_height(),
        transp,
        tx_data.sapling_bundle().cloned(),
    ))
}

/// Verify a shielded transaction.
pub fn verify_shielded_tx(transaction: &Transaction) -> bool {
    tracing::info!("entered verify_shielded_tx()");

    let sapling_bundle = if let Some(bundle) = transaction.sapling_bundle() {
        bundle
    } else {
        return false;
    };
    let tx_data = transaction.deref();

    // Partially deauthorize the transparent bundle
    let unauth_tx_data = match partial_deauthorize(tx_data) {
        Some(tx_data) => tx_data,
        None => return false,
    };

    let txid_parts = unauth_tx_data.digest(TxIdDigester);
    // the commitment being signed is shared across all Sapling inputs; once
    // V4 transactions are deprecated this should just be the txid, but
    // for now we need to continue to compute it here.
    let sighash =
        signature_hash(&unauth_tx_data, &SignableInput::Shielded, &txid_parts);

    tracing::info!("sighash computed");

    let PVKs {
        spend_vk,
        convert_vk,
        output_vk,
    } = load_pvks();

    #[cfg(not(feature = "testing"))]
    let mut ctx = SaplingVerificationContext::new(true);
    #[cfg(feature = "testing")]
    let mut ctx = testing::MockSaplingVerificationContext::new(true);
    let spends_valid = sapling_bundle
        .shielded_spends
        .iter()
        .all(|spend| check_spend(spend, sighash.as_ref(), &mut ctx, spend_vk));
    let converts_valid = sapling_bundle
        .shielded_converts
        .iter()
        .all(|convert| check_convert(convert, &mut ctx, convert_vk));
    let outputs_valid = sapling_bundle
        .shielded_outputs
        .iter()
        .all(|output| check_output(output, &mut ctx, output_vk));

    if !(spends_valid && outputs_valid && converts_valid) {
        return false;
    }

    tracing::info!("passed spend/output verification");

    let assets_and_values: I128Sum = sapling_bundle.value_balance.clone();

    tracing::info!(
        "accumulated {} assets/values",
        assets_and_values.components().len()
    );

    let result = ctx.final_check(
        assets_and_values,
        sighash.as_ref(),
        sapling_bundle.authorization.binding_sig,
    );
    tracing::info!("final check result {result}");
    result
}

/// Get the path to MASP parameters from [`ENV_VAR_MASP_PARAMS_DIR`] env var or
/// use the default.
pub fn get_params_dir() -> PathBuf {
    if let Ok(params_dir) = env::var(ENV_VAR_MASP_PARAMS_DIR) {
        println!("Using {} as masp parameter folder.", params_dir);
        PathBuf::from(params_dir)
    } else {
        masp_proofs::default_params_folder().unwrap()
    }
}

/// Freeze a Builder into the format necessary for inclusion in a Tx. This is
/// the format used by hardware wallets to validate a MASP Transaction.
struct WalletMap;

impl<P1>
    masp_primitives::transaction::components::sapling::builder::MapBuilder<
        P1,
        ExtendedSpendingKey,
        (),
        ExtendedFullViewingKey,
    > for WalletMap
{
    fn map_params(&self, _s: P1) {}

    fn map_key(&self, s: ExtendedSpendingKey) -> ExtendedFullViewingKey {
        (&s).into()
    }
}

impl<P1, R1, N1>
    MapBuilder<
        P1,
        R1,
        ExtendedSpendingKey,
        N1,
        (),
        (),
        ExtendedFullViewingKey,
        (),
    > for WalletMap
{
    fn map_rng(&self, _s: R1) {}

    fn map_notifier(&self, _s: N1) {}
}

/// Abstracts platform specific details away from the logic of shielded pool
/// operations.
#[cfg_attr(feature = "async-send", async_trait::async_trait)]
#[cfg_attr(not(feature = "async-send"), async_trait::async_trait(?Send))]
pub trait ShieldedUtils:
    Sized + BorshDeserialize + BorshSerialize + Default + Clone
{
    /// Get a MASP transaction prover
    fn local_tx_prover(&self) -> LocalTxProver;

    /// Load up the currently saved ShieldedContext
    async fn load<U: ShieldedUtils + MaybeSend>(
        &self,
        ctx: &mut ShieldedContext<U>,
        force_confirmed: bool,
    ) -> std::io::Result<()>;

    /// Save the given ShieldedContext for future loads
    async fn save<U: ShieldedUtils + MaybeSync>(
        &self,
        ctx: &ShieldedContext<U>,
    ) -> std::io::Result<()>;
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
pub fn is_amount_required(src: I128Sum, dest: I128Sum, delta: I128Sum) -> bool {
    let gap = dest - src;
    for (asset_type, value) in gap.components() {
        if *value > 0 && delta[asset_type] > 0 {
            return true;
        }
    }
    false
}

/// a masp change
#[derive(BorshSerialize, BorshDeserialize, Debug, Clone)]
pub struct MaspChange {
    /// the token address
    pub asset: Address,
    /// the change in the token
    pub change: token::Change,
}

/// a masp amount
pub type MaspAmount = ValueSum<(Option<Epoch>, Address), token::Change>;

/// An extension of Option's cloned method for pair types
fn cloned_pair<T: Clone, U: Clone>((a, b): (&T, &U)) -> (T, U) {
    (a.clone(), b.clone())
}

/// Represents the amount used of different conversions
pub type Conversions =
    BTreeMap<AssetType, (AllowedConversion, MerklePath<Node>, i128)>;

/// Represents the changes that were made to a list of transparent accounts
pub type TransferDelta = HashMap<Address, MaspChange>;

/// Represents the changes that were made to a list of shielded accounts
pub type TransactionDelta = HashMap<ViewingKey, I128Sum>;
/// A cache of fetched indexed transactions.
///
/// The cache is designed so that it either contains
/// all transactions from a given height, or none.
#[derive(BorshSerialize, BorshDeserialize, Debug, Default, Clone)]
pub struct Unscanned {
    txs: IndexedNoteData,
}

impl Unscanned {
    fn extend<I>(&mut self, items: I)
    where
        I: IntoIterator<Item = IndexedNoteEntry>,
    {
        self.txs.extend(items);
    }

    fn contains_height(&self, height: u64) -> bool {
        self.txs.keys().any(|k| k.height.0 == height)
    }

    /// We remove all indices from blocks that have been entirely scanned.
    /// If a block is only partially scanned, we leave all the events in the
    /// cache.
    fn scanned(&mut self, ix: &IndexedTx) {
        self.txs.retain(|i, _| i.height >= ix.height);
    }
}

impl IntoIterator for Unscanned {
    type IntoIter = <IndexedNoteData as IntoIterator>::IntoIter;
    type Item = IndexedNoteEntry;

    fn into_iter(self) -> Self::IntoIter {
        self.txs.into_iter()
    }
}

#[derive(BorshSerialize, BorshDeserialize, Debug)]
/// The possible sync states of the shielded context
pub enum ContextSyncStatus {
    /// The context contains only data that has been confirmed by the protocol
    Confirmed,
    /// The context contains that that has not yet been confirmed by the
    /// protocol and could end up being invalid
    Speculative,
}

/// Represents the current state of the shielded pool from the perspective of
/// the chosen viewing keys.
#[derive(BorshSerialize, BorshDeserialize, Debug)]
pub struct ShieldedContext<U: ShieldedUtils> {
    /// Location where this shielded context is saved
    #[borsh(skip)]
    pub utils: U,
    /// The commitment tree produced by scanning all transactions up to tx_pos
    pub tree: CommitmentTree<Node>,
    /// Maps viewing keys to the block height to which they are synced.
    /// In particular, the height given by the value *has been scanned*.
    pub vk_heights: BTreeMap<ViewingKey, Option<IndexedTx>>,
    /// Maps viewing keys to applicable note positions
    pub pos_map: HashMap<ViewingKey, BTreeSet<usize>>,
    /// Maps a nullifier to the note position to which it applies
    pub nf_map: HashMap<Nullifier, usize>,
    /// Maps note positions to their corresponding notes
    pub note_map: HashMap<usize, Note>,
    /// Maps note positions to their corresponding memos
    pub memo_map: HashMap<usize, MemoBytes>,
    /// Maps note positions to the diversifier of their payment address
    pub div_map: HashMap<usize, Diversifier>,
    /// Maps note positions to their witness (used to make merkle paths)
    pub witness_map: HashMap<usize, IncrementalWitness<Node>>,
    /// Tracks what each transaction does to various account balances
    pub delta_map:
        BTreeMap<IndexedTx, (Epoch, TransferDelta, TransactionDelta)>,
    /// The set of note positions that have been spent
    pub spents: HashSet<usize>,
    /// Maps asset types to their decodings
    pub asset_types: HashMap<AssetType, AssetData>,
    /// Maps note positions to their corresponding viewing keys
    pub vk_map: HashMap<usize, ViewingKey>,
    /// Maps a shielded tx to the index of its first output note.
    pub tx_note_map: BTreeMap<IndexedTx, usize>,
    /// A cache of fetched indexed txs.
    pub unscanned: Unscanned,
    /// The sync state of the context
    pub sync_status: ContextSyncStatus,
}

/// Default implementation to ease construction of TxContexts. Derive cannot be
/// used here due to CommitmentTree not implementing Default.
impl<U: ShieldedUtils + Default> Default for ShieldedContext<U> {
    fn default() -> ShieldedContext<U> {
        ShieldedContext::<U> {
            utils: U::default(),
            vk_heights: BTreeMap::new(),
            tx_note_map: BTreeMap::default(),
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
            unscanned: Default::default(),
            sync_status: ContextSyncStatus::Confirmed,
        }
    }
}

impl<U: ShieldedUtils + MaybeSend + MaybeSync> ShieldedContext<U> {
    /// Try to load the last saved shielded context from the given context
    /// directory. If this fails, then leave the current context unchanged.
    pub async fn load(&mut self) -> std::io::Result<()> {
        self.utils.clone().load(self, false).await
    }

    /// Try to load the last saved confirmed shielded context from the given
    /// context directory. If this fails, then leave the current context
    /// unchanged.
    pub async fn load_confirmed(&mut self) -> std::io::Result<()> {
        self.utils.clone().load(self, true).await?;

        Ok(())
    }

    /// Save this shielded context into its associated context directory. If the
    /// state to be saved is confirmed than also delete the speculative one (if
    /// available)
    pub async fn save(&self) -> std::io::Result<()> {
        self.utils.save(self).await
    }

    /// Update the merkle tree of witnesses the first time we
    /// scan a new MASP transaction.
    fn update_witness_map(
        &mut self,
        indexed_tx: IndexedTx,
        shielded: &Transaction,
    ) -> Result<(), Error> {
        let mut note_pos = self.tree.size();
        self.tx_note_map.insert(indexed_tx, note_pos);
        for so in shielded
            .sapling_bundle()
            .map_or(&vec![], |x| &x.shielded_outputs)
        {
            // Create merkle tree leaf node from note commitment
            let node = Node::new(so.cmu.to_repr());
            // Update each merkle tree in the witness map with the latest
            // addition
            for (_, witness) in self.witness_map.iter_mut() {
                witness.append(node).map_err(|()| {
                    Error::Other("note commitment tree is full".to_string())
                })?;
            }
            self.tree.append(node).map_err(|()| {
                Error::Other("note commitment tree is full".to_string())
            })?;
            // Finally, make it easier to construct merkle paths to this new
            // note
            let witness = IncrementalWitness::<Node>::from_tree(&self.tree);
            self.witness_map.insert(note_pos, witness);
            note_pos += 1;
        }
        Ok(())
    }

    /// Fetch the current state of the multi-asset shielded pool into a
    /// ShieldedContext
    pub async fn fetch<C: Client + Sync, IO: Io>(
        &mut self,
        client: &C,
        logger: &impl ProgressLogger<IO>,
        last_query_height: Option<BlockHeight>,
        _batch_size: u64,
        sks: &[ExtendedSpendingKey],
        fvks: &[ViewingKey],
    ) -> Result<(), Error> {
        // add new viewing keys
        // Reload the state from file to get the last confirmed state and
        // discard any speculative data, we cannot fetch on top of a
        // speculative state
        // Always reload the confirmed context or initialize a new one if not
        // found
        if self.load_confirmed().await.is_err() {
            // Initialize a default context if we couldn't load a valid one
            // from storage
            *self = Self {
                utils: std::mem::take(&mut self.utils),
                ..Default::default()
            };
        }

        for esk in sks {
            let vk = to_viewing_key(esk).vk;
            self.vk_heights.entry(vk).or_default();
        }
        for vk in fvks {
            self.vk_heights.entry(*vk).or_default();
        }
        let _ = self.save().await;
        let native_token = query_native_token(client).await?;
        // the latest block height which has been added to the witness Merkle
        // tree
        let Some(least_idx) = self.vk_heights.values().min().cloned() else {
            return Ok(());
        };
        let last_witnessed_tx = self.tx_note_map.keys().max().cloned();
        // get the bounds on the block heights to fetch
        let start_idx =
            std::cmp::min(last_witnessed_tx, least_idx).map(|ix| ix.height);
        // Load all transactions accepted until this point
        // N.B. the cache is a hash map
        self.unscanned.extend(
            self.fetch_shielded_transfers(
                client,
                logger,
                start_idx,
                last_query_height,
            )
            .await?,
        );
        // persist the cache in case of interruptions.
        let _ = self.save().await;

        let txs = logger.scan(self.unscanned.clone());
        for (indexed_tx, (epoch, tx, stx)) in txs {
            if Some(indexed_tx) > last_witnessed_tx {
                self.update_witness_map(indexed_tx, &stx)?;
            }
            let mut vk_heights = BTreeMap::new();
            std::mem::swap(&mut vk_heights, &mut self.vk_heights);
            for (vk, h) in vk_heights
                .iter_mut()
                .filter(|(_vk, h)| **h < Some(indexed_tx))
            {
                self.scan_tx(
                    indexed_tx,
                    epoch,
                    &tx,
                    &stx,
                    vk,
                    native_token.clone(),
                )?;
                *h = Some(indexed_tx);
            }
            // possibly remove unneeded elements from the cache.
            self.unscanned.scanned(&indexed_tx);
            std::mem::swap(&mut vk_heights, &mut self.vk_heights);
            let _ = self.save().await;
        }

        Ok(())
    }

    /// Obtain a chronologically-ordered list of all accepted shielded
    /// transactions from a node.
    pub async fn fetch_shielded_transfers<C: Client + Sync, IO: Io>(
        &self,
        client: &C,
        logger: &impl ProgressLogger<IO>,
        last_indexed_tx: Option<BlockHeight>,
        last_query_height: Option<BlockHeight>,
    ) -> Result<IndexedNoteData, Error> {
        // Query for the last produced block height
        let last_block_height = query_block(client)
            .await?
            .map_or_else(BlockHeight::first, |block| block.height);
        let last_query_height = last_query_height.unwrap_or(last_block_height);

        let mut shielded_txs = BTreeMap::new();
        // Fetch all the transactions we do not have yet
        let first_height_to_query =
            last_indexed_tx.map_or_else(|| 1, |last| last.0);
        let heights = logger.fetch(first_height_to_query..=last_query_height.0);
        for height in heights {
            if self.unscanned.contains_height(height) {
                continue;
            }
            // Get the valid masp transactions at the specified height
            let epoch = query_epoch_at_height(client, height.into())
                .await?
                .ok_or_else(|| {
                    Error::from(QueryError::General(
                        "Queried height is greater than the last committed \
                         block height"
                            .to_string(),
                    ))
                })?;

            let txs_results = match get_indexed_masp_events_at_height(
                client,
                height.into(),
                None,
            )
            .await?
            {
                Some(events) => events,
                None => continue,
            };

            // Query the actual block to get the txs bytes. If we only need one
            // tx it might be slightly better to query the /tx endpoint to
            // reduce the amount of data sent over the network, but this is a
            // minimal improvement and it's even hard to tell how many times
            // we'd need a single masp tx to make this worth it
            let block = client
                .block(height as u32)
                .await
                .map_err(|e| Error::from(QueryError::General(e.to_string())))?
                .block
                .data;

            for (idx, tx_event) in txs_results {
                let tx = Tx::try_from(block[idx.0 as usize].as_ref())
                    .map_err(|e| Error::Other(e.to_string()))?;
                let (changed_keys, masp_transaction) = Self::extract_masp_tx(
                    &tx,
                    ExtractShieldedActionArg::Event::<C>(&tx_event),
                    true,
                )
                .await?;

                // Collect the current transaction
                shielded_txs.insert(
                    IndexedTx {
                        height: height.into(),
                        index: idx,
                    },
                    (epoch, changed_keys, masp_transaction),
                );
            }
        }

        Ok(shielded_txs)
    }

    /// Extract the relevant shield portions of a [`Tx`], if any.
    async fn extract_masp_tx<'args, C: Client + Sync>(
        tx: &Tx,
        action_arg: ExtractShieldedActionArg<'args, C>,
        check_header: bool,
    ) -> Result<(BTreeSet<namada_core::storage::Key>, Transaction), Error> {
        let maybe_transaction = if check_header {
            let tx_header = tx.header();
            // NOTE: simply looking for masp sections attached to the tx
            // is not safe. We don't validate the sections attached to a
            // transaction se we could end up with transactions carrying
            // an unnecessary masp section. We must instead look for the
            // required masp sections in the signed commitments (hashes)
            // of the transactions' headers/data sections
            if let Some(wrapper_header) = tx_header.wrapper() {
                let hash =
                    wrapper_header.unshield_section_hash.ok_or_else(|| {
                        Error::Other(
                            "Missing expected fee unshielding section hash"
                                .to_string(),
                        )
                    })?;

                let masp_transaction = tx
                    .get_section(&hash)
                    .ok_or_else(|| {
                        Error::Other(
                            "Missing expected masp section".to_string(),
                        )
                    })?
                    .masp_tx()
                    .ok_or_else(|| {
                        Error::Other("Missing masp transaction".to_string())
                    })?;

                // We use the changed keys instead of the Transfer object
                // because those are what the masp validity predicate works on
                let changed_keys =
                    if let ExtractShieldedActionArg::Event(tx_event) =
                        action_arg
                    {
                        let tx_result_str = tx_event
                            .attributes
                            .iter()
                            .find_map(|attr| {
                                if attr.key == "inner_tx" {
                                    Some(&attr.value)
                                } else {
                                    None
                                }
                            })
                            .ok_or_else(|| {
                                Error::Other(
                                    "Missing required tx result in event"
                                        .to_string(),
                                )
                            })?;
                        TxResult::from_str(tx_result_str)
                            .map_err(|e| Error::Other(e.to_string()))?
                            .changed_keys
                    } else {
                        BTreeSet::default()
                    };

                Some((changed_keys, masp_transaction))
            } else {
                None
            }
        } else {
            None
        };

        let result = if let Some(tx) = maybe_transaction {
            tx
        } else {
            // Expect decrypted transaction
            let tx_data = tx.data().ok_or_else(|| {
                Error::Other("Missing data section".to_string())
            })?;
            match Transfer::try_from_slice(&tx_data) {
                Ok(transfer) => {
                    let masp_transaction = tx
                        .get_section(&transfer.shielded.ok_or_else(|| {
                            Error::Other(
                                "Missing masp section hash".to_string(),
                            )
                        })?)
                        .ok_or_else(|| {
                            Error::Other(
                                "Missing masp section in transaction"
                                    .to_string(),
                            )
                        })?
                        .masp_tx()
                        .ok_or_else(|| {
                            Error::Other("Missing masp transaction".to_string())
                        })?;

                    // We use the changed keys instead of the Transfer object
                    // because those are what the masp validity predicate works
                    // on
                    let changed_keys =
                        if let ExtractShieldedActionArg::Event(tx_event) =
                            action_arg
                        {
                            let tx_result_str = tx_event
                                .attributes
                                .iter()
                                .find_map(|attr| {
                                    if attr.key == "inner_tx" {
                                        Some(&attr.value)
                                    } else {
                                        None
                                    }
                                })
                                .ok_or_else(|| {
                                    Error::Other(
                                        "Missing required tx result in event"
                                            .to_string(),
                                    )
                                })?;
                            TxResult::from_str(tx_result_str)
                                .map_err(|e| Error::Other(e.to_string()))?
                                .changed_keys
                        } else {
                            BTreeSet::default()
                        };
                    (changed_keys, masp_transaction)
                }
                Err(_) => {
                    // This should be a MASP over IBC transaction, it
                    // could be a ShieldedTransfer or an Envelope
                    // message, need to try both

                    extract_payload_from_shielded_action::<C>(
                        &tx_data, action_arg,
                    )
                    .await?
                }
            }
        };
        Ok(result)
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
        indexed_tx: IndexedTx,
        epoch: Epoch,
        tx_changed_keys: &BTreeSet<namada_core::storage::Key>,
        shielded: &Transaction,
        vk: &ViewingKey,
        native_token: Address,
    ) -> Result<(), Error> {
        // For tracking the account changes caused by this Transaction
        let mut transaction_delta = TransactionDelta::new();
        if let ContextSyncStatus::Confirmed = self.sync_status {
            let mut note_pos = self.tx_note_map[&indexed_tx];
            // Listen for notes sent to our viewing keys, only if we are syncing
            // (i.e. in a confirmed status)
            for so in shielded
                .sapling_bundle()
                .map_or(&vec![], |x| &x.shielded_outputs)
            {
                // Let's try to see if this viewing key can decrypt latest
                // note
                let notes = self.pos_map.entry(*vk).or_default();
                let decres = try_sapling_note_decryption::<_, OutputDescription<<<Authorized as Authorization>::SaplingAuth as masp_primitives::transaction::components::sapling::Authorization>::Proof>>(
                &NETWORK,
                1.into(),
                &PreparedIncomingViewingKey::new(&vk.ivk()),
                so,
            );
                // So this current viewing key does decrypt this current note...
                if let Some((note, pa, memo)) = decres {
                    // Add this note to list of notes decrypted by this viewing
                    // key
                    notes.insert(note_pos);
                    // Compute the nullifier now to quickly recognize when spent
                    let nf = note.nf(
                        &vk.nk,
                        note_pos.try_into().map_err(|_| {
                            Error::Other("Can not get nullifier".to_string())
                        })?,
                    );
                    self.note_map.insert(note_pos, note);
                    self.memo_map.insert(note_pos, memo);
                    // The payment address' diversifier is required to spend
                    // note
                    self.div_map.insert(note_pos, *pa.diversifier());
                    self.nf_map.insert(nf, note_pos);
                    // Note the account changes
                    let balance = transaction_delta
                        .entry(*vk)
                        .or_insert_with(I128Sum::zero);
                    *balance += I128Sum::from_nonnegative(
                        note.asset_type,
                        note.value as i128,
                    )
                    .map_err(|()| {
                        Error::Other(
                            "found note with invalid value or asset type"
                                .to_string(),
                        )
                    })?;
                    self.vk_map.insert(note_pos, *vk);
                }
                note_pos += 1;
            }
        }

        // Cancel out those of our notes that have been spent
        for ss in shielded
            .sapling_bundle()
            .map_or(&vec![], |x| &x.shielded_spends)
        {
            // If the shielded spend's nullifier is in our map, then target note
            // is rendered unusable
            if let Some(note_pos) = self.nf_map.get(&ss.nullifier) {
                self.spents.insert(*note_pos);
                // Note the account changes
                let balance = transaction_delta
                    .entry(self.vk_map[note_pos])
                    .or_insert_with(I128Sum::zero);
                let note = self.note_map[note_pos];

                *balance -= I128Sum::from_nonnegative(
                    note.asset_type,
                    note.value as i128,
                )
                .map_err(|()| {
                    Error::Other(
                        "found note with invalid value or asset type"
                            .to_string(),
                    )
                })?;
            }
        }
        // Record the changes to the transparent accounts
        let mut transfer_delta = TransferDelta::new();

        let balance_keys: Vec<_> = tx_changed_keys
            .iter()
            .filter_map(is_any_shielded_action_balance_key)
            .collect();
        let (source, token, amount) = match shielded.transparent_bundle() {
            Some(transp_bundle) => {
                // Shielding/Unshielding transfer
                match (transp_bundle.vin.len(), transp_bundle.vout.len()) {
                    (0, 0) => {
                        return Err(Error::Other(
                            "Expected shielding/unshielding transaction"
                                .to_string(),
                        ));
                    }
                    (_, 0) => {
                        // Shielding, only if we are syncing. If in
                        // speculative context do not update
                        if let ContextSyncStatus::Confirmed = self.sync_status {
                            let addresses = balance_keys
                                .iter()
                                .find(|addresses| {
                                    if addresses[1] != &MASP {
                                        let transp_addr_commit =
                                            TransparentAddress(
                                                ripemd::Ripemd160::digest(
                                                    sha2::Sha256::digest(
                                                        &addresses[1]
                                                            .serialize_to_vec(),
                                                    ),
                                                )
                                                .into(),
                                            );
                                        // Vins contain the same address, so we
                                        // can
                                        // just examine the first one
                                        transp_bundle.vin.first().is_some_and(
                                            |vin| {
                                                vin.address
                                                    == transp_addr_commit
                                            },
                                        )
                                    } else {
                                        false
                                    }
                                })
                                .ok_or_else(|| {
                                    Error::Other(
                                        "Could not find source of MASP tx"
                                            .to_string(),
                                    )
                                })?;

                            let amount = transp_bundle
                                .vin
                                .iter()
                                .fold(Amount::zero(), |acc, vin| {
                                    acc + Amount::from_u64(vin.value)
                                });

                            (
                                addresses[1].to_owned(),
                                addresses[0].to_owned(),
                                amount,
                            )
                        } else {
                            return Ok(());
                        }
                    }
                    (0, _) => {
                        // Unshielding
                        let token = balance_keys
                            .iter()
                            .find(|addresses| {
                                if addresses[1] != &MASP {
                                    let transp_addr_commit = TransparentAddress(
                                        ripemd::Ripemd160::digest(
                                            sha2::Sha256::digest(
                                                &addresses[1]
                                                    .serialize_to_vec(),
                                            ),
                                        )
                                        .into(),
                                    );

                                    // Vouts contain the same address, so we
                                    // can
                                    // just examine the first one
                                    transp_bundle.vout.first().is_some_and(
                                        |vout| {
                                            vout.address == transp_addr_commit
                                        },
                                    )
                                } else {
                                    false
                                }
                            })
                            .ok_or_else(|| {
                                Error::Other(
                                    "Could not find target of MASP tx"
                                        .to_string(),
                                )
                            })?[0];

                        let amount = transp_bundle
                            .vout
                            .iter()
                            .fold(Amount::zero(), |acc, vout| {
                                acc + Amount::from_u64(vout.value)
                            });
                        (MASP, token.to_owned(), amount)
                    }
                    (_, _) => {
                        return Err(Error::Other(
                            "MASP transaction cannot contain both transparent \
                             inputs and outputs"
                                .to_string(),
                        ));
                    }
                }
            }
            None => {
                // Shielded transfer
                (MASP, native_token, Amount::zero())
            }
        };

        transfer_delta.insert(
            source,
            MaspChange {
                asset: token,
                change: -amount.change(),
            },
        );
        self.delta_map
            .insert(indexed_tx, (epoch, transfer_delta, transaction_delta));
        Ok(())
    }

    /// Summarize the effects on shielded and transparent accounts of each
    /// Transfer in this context
    pub fn get_tx_deltas(
        &self,
    ) -> &BTreeMap<IndexedTx, (Epoch, TransferDelta, TransactionDelta)> {
        &self.delta_map
    }

    /// Compute the total unspent notes associated with the viewing key in the
    /// context. If the key is not in the context, then we do not know the
    /// balance and hence we return None.
    pub async fn compute_shielded_balance(
        &mut self,
        vk: &ViewingKey,
    ) -> Result<Option<I128Sum>, Error> {
        // Cannot query the balance of a key that's not in the map
        if !self.pos_map.contains_key(vk) {
            return Ok(None);
        }
        let mut val_acc = I128Sum::zero();
        // Retrieve the notes that can be spent by this key
        if let Some(avail_notes) = self.pos_map.get(vk) {
            for note_idx in avail_notes {
                // Spent notes cannot contribute a new transaction's pool
                if self.spents.contains(note_idx) {
                    continue;
                }
                // Get note associated with this ID
                let note = self.note_map.get(note_idx).ok_or_else(|| {
                    Error::Other(format!("Unable to get note {note_idx}"))
                })?;
                // Finally add value to multi-asset accumulator
                val_acc += I128Sum::from_nonnegative(
                    note.asset_type,
                    note.value as i128,
                )
                .map_err(|()| {
                    Error::Other(
                        "found note with invalid value or asset type"
                            .to_string(),
                    )
                })?
            }
        }
        Ok(Some(val_acc))
    }

    /// Use the addresses already stored in the wallet to precompute as many
    /// asset types as possible.
    pub async fn precompute_asset_types<C: Client + Sync>(
        &mut self,
        client: &C,
        tokens: Vec<&Address>,
    ) -> Result<(), Error> {
        // To facilitate lookups of human-readable token names
        for token in tokens {
            let Some(denom) = query_denom(client, token).await else {
                return Err(Error::Query(QueryError::General(format!(
                    "denomination for token {token}"
                ))));
            };
            for position in MaspDigitPos::iter() {
                let asset_type =
                    encode_asset_type(token.clone(), denom, position, None)
                        .map_err(|_| {
                            Error::Other(
                                "unable to create asset type".to_string(),
                            )
                        })?;
                self.asset_types.insert(
                    asset_type,
                    AssetData {
                        token: token.clone(),
                        denom,
                        position,
                        epoch: None,
                    },
                );
            }
        }
        Ok(())
    }

    /// Query the ledger for the decoding of the given asset type and cache it
    /// if it is found.
    pub async fn decode_asset_type<C: Client + Sync>(
        &mut self,
        client: &C,
        asset_type: AssetType,
    ) -> Option<AssetData> {
        // Try to find the decoding in the cache
        if let decoded @ Some(_) = self.asset_types.get(&asset_type) {
            return decoded.cloned();
        }
        // Query for the ID of the last accepted transaction
        let (token, denom, position, ep, _conv, _path): (
            Address,
            Denomination,
            MaspDigitPos,
            _,
            I128Sum,
            MerklePath<Node>,
        ) = rpc::query_conversion(client, asset_type).await?;
        let pre_asset_type = AssetData {
            token,
            denom,
            position,
            epoch: Some(ep),
        };
        self.asset_types.insert(asset_type, pre_asset_type.clone());
        Some(pre_asset_type)
    }

    /// Query the ledger for the conversion that is allowed for the given asset
    /// type and cache it.
    async fn query_allowed_conversion<'a, C: Client + Sync>(
        &'a mut self,
        client: &C,
        asset_type: AssetType,
        conversions: &'a mut Conversions,
    ) {
        if let btree_map::Entry::Vacant(conv_entry) =
            conversions.entry(asset_type)
        {
            // Query for the ID of the last accepted transaction
            let Some((token, denom, position, ep, conv, path)) =
                query_conversion(client, asset_type).await
            else {
                return;
            };
            self.asset_types.insert(
                asset_type,
                AssetData {
                    token,
                    denom,
                    position,
                    epoch: Some(ep),
                },
            );
            // If the conversion is 0, then we just have a pure decoding
            if !conv.is_zero() {
                conv_entry.insert((conv.into(), path, 0));
            }
        }
    }

    /// Compute the total unspent notes associated with the viewing key in the
    /// context and express that value in terms of the currently timestamped
    /// asset types. If the key is not in the context, then we do not know the
    /// balance and hence we return None.
    pub async fn compute_exchanged_balance(
        &mut self,
        client: &(impl Client + Sync),
        io: &impl Io,
        vk: &ViewingKey,
        target_epoch: Epoch,
    ) -> Result<Option<I128Sum>, Error> {
        // First get the unexchanged balance
        if let Some(balance) = self.compute_shielded_balance(vk).await? {
            let exchanged_amount = self
                .compute_exchanged_amount(
                    client,
                    io,
                    balance,
                    target_epoch,
                    BTreeMap::new(),
                )
                .await?
                .0;
            // And then exchange balance into current asset types
            Ok(Some(exchanged_amount))
        } else {
            Ok(None)
        }
    }

    /// Try to convert as much of the given asset type-value pair using the
    /// given allowed conversion. usage is incremented by the amount of the
    /// conversion used, the conversions are applied to the given input, and
    /// the trace amount that could not be converted is moved from input to
    /// output.
    #[allow(clippy::too_many_arguments)]
    async fn apply_conversion(
        &mut self,
        io: &impl Io,
        conv: AllowedConversion,
        asset_type: AssetType,
        value: i128,
        usage: &mut i128,
        input: &mut I128Sum,
        output: &mut I128Sum,
        normed_asset_type: AssetType,
        normed_output: &mut I128Sum,
    ) -> Result<(), Error> {
        // we do not need to convert negative values
        if value <= 0 {
            return Ok(());
        }
        // If conversion if possible, accumulate the exchanged amount
        let conv: I128Sum = I128Sum::from_sum(conv.into());
        // The amount required of current asset to qualify for conversion
        let threshold = -conv[&asset_type];
        if threshold == 0 {
            edisplay_line!(
                io,
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
        let trace = I128Sum::from_pair(asset_type, value % threshold)
            .expect("the trace should be a valid i128");
        let normed_trace =
            I128Sum::from_pair(normed_asset_type, value % threshold)
                .expect("the trace should be a valid i128");
        // Record how much more of the given conversion has been used
        *usage += required;
        // Apply the conversions to input and move the trace amount to output
        *input += conv * required - trace.clone();
        *output += trace;
        *normed_output += normed_trace;
        Ok(())
    }

    /// Convert the given amount into the latest asset types whilst making a
    /// note of the conversions that were used. Note that this function does
    /// not assume that allowed conversions from the ledger are expressed in
    /// terms of the latest asset types.
    pub async fn compute_exchanged_amount(
        &mut self,
        client: &(impl Client + Sync),
        io: &impl Io,
        mut input: I128Sum,
        target_epoch: Epoch,
        mut conversions: Conversions,
    ) -> Result<(I128Sum, I128Sum, Conversions), Error> {
        // Where we will store our exchanged value
        let mut output = I128Sum::zero();
        // Where we will store our normed exchanged value
        let mut normed_output = I128Sum::zero();
        // Repeatedly exchange assets until it is no longer possible
        while let Some((asset_type, value)) =
            input.components().next().map(cloned_pair)
        {
            // Get the equivalent to the current asset in the target epoch and
            // note whether this equivalent chronologically comes after the
            // current asset
            let (target_asset_type, forward_conversion) = self
                .decode_asset_type(client, asset_type)
                .await
                .map(|mut pre_asset_type| {
                    let old_epoch = pre_asset_type.redate(target_epoch);
                    pre_asset_type
                        .encode()
                        .map(|asset_type| {
                            (
                                asset_type,
                                old_epoch.map_or(false, |epoch| {
                                    target_epoch >= epoch
                                }),
                            )
                        })
                        .map_err(|_| {
                            Error::Other(
                                "unable to create asset type".to_string(),
                            )
                        })
                })
                .transpose()?
                .unwrap_or((asset_type, false));
            let at_target_asset_type = target_asset_type == asset_type;
            let trace_asset_type = if forward_conversion {
                // If we are doing a forward conversion, then we can assume that
                // the trace left over in the older epoch has at least a 1-to-1
                // conversion to the newer epoch.
                target_asset_type
            } else {
                // If we are not doing a forward conversion, then we cannot
                // lower bound what the asset type will be worth in the target
                // asset type. So leave the asset type fixed.
                asset_type
            };
            // Fetch and store the required conversions
            self.query_allowed_conversion(
                client,
                target_asset_type,
                &mut conversions,
            )
            .await;
            self.query_allowed_conversion(client, asset_type, &mut conversions)
                .await;
            if let (Some((conv, _wit, usage)), false) =
                (conversions.get_mut(&asset_type), at_target_asset_type)
            {
                display_line!(
                    io,
                    "converting current asset type to latest asset type..."
                );
                // Not at the target asset type, not at the latest asset
                // type. Apply conversion to get from
                // current asset type to the latest
                // asset type.
                self.apply_conversion(
                    io,
                    conv.clone(),
                    asset_type,
                    value,
                    usage,
                    &mut input,
                    &mut output,
                    trace_asset_type,
                    &mut normed_output,
                )
                .await?;
            } else if let (Some((conv, _wit, usage)), false) = (
                conversions.get_mut(&target_asset_type),
                at_target_asset_type,
            ) {
                display_line!(
                    io,
                    "converting latest asset type to target asset type..."
                );
                // Not at the target asset type, yet at the latest asset
                // type. Apply inverse conversion to get
                // from latest asset type to the target
                // asset type.
                self.apply_conversion(
                    io,
                    conv.clone(),
                    asset_type,
                    value,
                    usage,
                    &mut input,
                    &mut output,
                    trace_asset_type,
                    &mut normed_output,
                )
                .await?;
            } else {
                // At the target asset type. Then move component over to
                // output.
                let comp = input.project(asset_type);
                output += comp.clone();
                normed_output += comp.clone();
                input -= comp;
            }
        }
        Ok((output, normed_output, conversions))
    }

    /// Collect enough unspent notes in this context to exceed the given amount
    /// of the specified asset type. Return the total value accumulated plus
    /// notes and the corresponding diversifiers/merkle paths that were used to
    /// achieve the total value.
    pub async fn collect_unspent_notes(
        &mut self,
        context: &impl Namada,
        vk: &ViewingKey,
        target: I128Sum,
        target_epoch: Epoch,
    ) -> Result<
        (
            I128Sum,
            Vec<(Diversifier, Note, MerklePath<Node>)>,
            Conversions,
        ),
        Error,
    > {
        // TODO: we should try to use the smallest notes possible to fund the
        // transaction to allow people to fetch less often
        // Establish connection with which to do exchange rate queries
        let mut conversions = BTreeMap::new();
        let mut val_acc = I128Sum::zero();
        let mut normed_val_acc = I128Sum::zero();
        let mut notes = Vec::new();
        // Retrieve the notes that can be spent by this key
        if let Some(avail_notes) = self.pos_map.get(vk).cloned() {
            for note_idx in &avail_notes {
                // No more transaction inputs are required once we have met
                // the target amount
                if normed_val_acc >= target {
                    break;
                }
                // Spent notes cannot contribute a new transaction's pool
                if self.spents.contains(note_idx) {
                    continue;
                }
                // Get note, merkle path, diversifier associated with this ID
                let note = *self.note_map.get(note_idx).ok_or_else(|| {
                    Error::Other(format!("Unable to get note {note_idx}"))
                })?;

                // The amount contributed by this note before conversion
                let pre_contr =
                    I128Sum::from_pair(note.asset_type, note.value as i128)
                        .map_err(|()| {
                            Error::Other(
                                "received note has invalid value or asset type"
                                    .to_string(),
                            )
                        })?;
                let (contr, normed_contr, proposed_convs) = self
                    .compute_exchanged_amount(
                        context.client(),
                        context.io(),
                        pre_contr,
                        target_epoch,
                        conversions.clone(),
                    )
                    .await?;

                // Use this note only if it brings us closer to our target
                if is_amount_required(
                    normed_val_acc.clone(),
                    target.clone(),
                    normed_contr.clone(),
                ) {
                    // Be sure to record the conversions used in computing
                    // accumulated value
                    val_acc += contr;
                    normed_val_acc += normed_contr;
                    // Commit the conversions that were used to exchange
                    conversions = proposed_convs;
                    let merkle_path = self
                        .witness_map
                        .get(note_idx)
                        .ok_or_else(|| {
                            Error::Other(format!(
                                "Unable to get note {note_idx}"
                            ))
                        })?
                        .path()
                        .ok_or_else(|| {
                            Error::Other(format!(
                                "Unable to get path: {}",
                                line!()
                            ))
                        })?;
                    let diversifier =
                        self.div_map.get(note_idx).ok_or_else(|| {
                            Error::Other(format!(
                                "Unable to get note {note_idx}"
                            ))
                        })?;
                    // Commit this note to our transaction
                    notes.push((*diversifier, note, merkle_path));
                }
            }
        }
        Ok((val_acc, notes, conversions))
    }

    /// Compute the combined value of the output notes of the transaction pinned
    /// at the given payment address. This computation uses the supplied viewing
    /// keys to try to decrypt the output notes. If no transaction is pinned at
    /// the given payment address fails with
    /// `PinnedBalanceError::NoTransactionPinned`.
    pub async fn compute_pinned_balance<C: Client + Sync>(
        client: &C,
        owner: PaymentAddress,
        viewing_key: &ViewingKey,
    ) -> Result<(I128Sum, Epoch), Error> {
        // Check that the supplied viewing key corresponds to given payment
        // address
        let counter_owner = viewing_key.to_payment_address(
            *masp_primitives::sapling::PaymentAddress::diversifier(
                &owner.into(),
            ),
        );
        match counter_owner {
            Some(counter_owner) if counter_owner == owner.into() => {}
            _ => {
                return Err(Error::from(PinnedBalanceError::InvalidViewingKey));
            }
        }
        // Construct the key for where the transaction ID would be stored
        let pin_key = namada_token::storage_key::masp_pin_tx_key(&owner.hash());
        // Obtain the transaction pointer at the key
        // If we don't discard the error message then a test fails,
        // however the error underlying this will go undetected
        let indexed_tx =
            rpc::query_storage_value::<C, IndexedTx>(client, &pin_key)
                .await
                .map_err(|_| PinnedBalanceError::NoTransactionPinned)?;
        let tx_epoch = query_epoch_at_height(client, indexed_tx.height)
            .await?
            .ok_or_else(|| {
                Error::from(QueryError::General(
                    "Queried height is greater than the last committed block \
                     height"
                        .to_string(),
                ))
            })?;

        let block = client
            .block(indexed_tx.height.0 as u32)
            .await
            .map_err(|e| Error::from(QueryError::General(e.to_string())))?
            .block
            .data;

        let tx = Tx::try_from(block[indexed_tx.index.0 as usize].as_ref())
            .map_err(|e| Error::Other(e.to_string()))?;
        let (_, shielded) = Self::extract_masp_tx(
            &tx,
            ExtractShieldedActionArg::Request((
                client,
                indexed_tx.height,
                Some(indexed_tx.index),
            )),
            false,
        )
        .await?;

        // Accumulate the combined output note value into this Amount
        let mut val_acc = I128Sum::zero();
        for so in shielded
            .sapling_bundle()
            .map_or(&vec![], |x| &x.shielded_outputs)
        {
            // Let's try to see if our viewing key can decrypt current note
            let decres = try_sapling_note_decryption::<_, OutputDescription<<<Authorized as Authorization>::SaplingAuth as masp_primitives::transaction::components::sapling::Authorization>::Proof>>(
                &NETWORK,
                1.into(),
                &PreparedIncomingViewingKey::new(&viewing_key.ivk()),
                so,
            );
            match decres {
                // So the given viewing key does decrypt this current note...
                Some((note, pa, _memo)) if pa == owner.into() => {
                    val_acc += I128Sum::from_nonnegative(
                        note.asset_type,
                        note.value as i128,
                    )
                    .map_err(|()| {
                        Error::Other(
                            "found note with invalid value or asset type"
                                .to_string(),
                        )
                    })?;
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
        context: &impl Namada,
        owner: PaymentAddress,
        viewing_key: &ViewingKey,
    ) -> Result<(ValueSum<Address, token::Change>, I128Sum, Epoch), Error> {
        // Obtain the balance that will be exchanged
        let (amt, ep) =
            Self::compute_pinned_balance(context.client(), owner, viewing_key)
                .await?;
        display_line!(context.io(), "Pinned balance: {:?}", amt);
        // Finally, exchange the balance to the transaction's epoch
        let computed_amount = self
            .compute_exchanged_amount(
                context.client(),
                context.io(),
                amt,
                ep,
                BTreeMap::new(),
            )
            .await?
            .0;
        display_line!(context.io(), "Exchanged amount: {:?}", computed_amount);
        let (decoded, undecoded) = self
            .decode_combine_sum_to_epoch(context.client(), computed_amount, ep)
            .await;
        Ok((decoded, undecoded, ep))
    }

    /// Convert an amount whose units are AssetTypes to one whose units are
    /// Addresses that they decode to. All asset types not corresponding to
    /// the given epoch are ignored.
    pub async fn decode_combine_sum_to_epoch<C: Client + Sync>(
        &mut self,
        client: &C,
        amt: I128Sum,
        target_epoch: Epoch,
    ) -> (ValueSum<Address, token::Change>, I128Sum) {
        let mut res = ValueSum::zero();
        let mut undecoded = ValueSum::zero();
        for (asset_type, val) in amt.components() {
            // Decode the asset type
            let decoded = self.decode_asset_type(client, *asset_type).await;
            // Only assets with the target timestamp count
            match decoded {
                Some(pre_asset_type)
                    if pre_asset_type
                        .epoch
                        .map_or(true, |epoch| epoch <= target_epoch) =>
                {
                    let decoded_change = token::Change::from_masp_denominated(
                        *val,
                        pre_asset_type.position,
                    )
                    .expect("expected this to fit");
                    res += ValueSum::from_pair(
                        pre_asset_type.token,
                        decoded_change,
                    )
                    .expect("expected this to fit");
                }
                None => {
                    undecoded += ValueSum::from_pair(*asset_type, *val)
                        .expect("expected this to fit");
                }
                _ => {}
            }
        }
        (res, undecoded)
    }

    /// Convert an amount whose units are AssetTypes to one whose units are
    /// Addresses that they decode to and combine the denominations.
    pub async fn decode_combine_sum<C: Client + Sync>(
        &mut self,
        client: &C,
        amt: I128Sum,
    ) -> (MaspAmount, I128Sum) {
        let mut res = MaspAmount::zero();
        let mut undecoded = ValueSum::zero();
        for (asset_type, val) in amt.components() {
            // Decode the asset type
            if let Some(decoded) =
                self.decode_asset_type(client, *asset_type).await
            {
                let decoded_change = token::Change::from_masp_denominated(
                    *val,
                    decoded.position,
                )
                .expect("expected this to fit");
                res += MaspAmount::from_pair(
                    (decoded.epoch, decoded.token),
                    decoded_change,
                )
                .expect("unable to construct decoded amount");
            } else {
                undecoded += ValueSum::from_pair(*asset_type, *val)
                    .expect("expected this to fit");
            }
        }
        (res, undecoded)
    }

    /// Convert an amount whose units are AssetTypes to one whose units are
    /// Addresses that they decode to.
    pub async fn decode_sum<C: Client + Sync>(
        &mut self,
        client: &C,
        amt: I128Sum,
    ) -> ValueSum<(AssetType, AssetData), i128> {
        let mut res = ValueSum::zero();
        for (asset_type, val) in amt.components() {
            // Decode the asset type
            if let Some(decoded) =
                self.decode_asset_type(client, *asset_type).await
            {
                res += ValueSum::from_pair((*asset_type, decoded), *val)
                    .expect("unable to construct decoded amount");
            }
        }
        res
    }

    /// Make shielded components to embed within a Transfer object. If no
    /// shielded payment address nor spending key is specified, then no
    /// shielded components are produced. Otherwise a transaction containing
    /// nullifiers and/or note commitments are produced. Dummy transparent
    /// UTXOs are sometimes used to make transactions balanced, but it is
    /// understood that transparent account changes are effected only by the
    /// amounts and signatures specified by the containing Transfer object.
    pub async fn gen_shielded_transfer(
        context: &impl Namada,
        source: &TransferSource,
        target: &TransferTarget,
        token: &Address,
        amount: token::DenominatedAmount,
        update_ctx: bool,
    ) -> Result<Option<ShieldedTransfer>, TransferErr> {
        // No shielded components are needed when neither source nor destination
        // are shielded

        use rand::rngs::StdRng;
        use rand_core::SeedableRng;

        let spending_key = source.spending_key();
        let payment_address = target.payment_address();
        // No shielded components are needed when neither source nor
        // destination are shielded
        if spending_key.is_none() && payment_address.is_none() {
            return Ok(None);
        }
        // We want to fund our transaction solely from supplied spending key
        let spending_key = spending_key.map(|x| x.into());
        {
            // Load the current shielded context given the spending key we
            // possess
            let mut shielded = context.shielded_mut().await;
            let _ = shielded.load().await;
        }
        // Determine epoch in which to submit potential shielded transaction
        let epoch = rpc::query_epoch(context.client()).await?;
        // Context required for storing which notes are in the source's
        // possession
        let memo = MemoBytes::empty();

        // Try to get a seed from env var, if any.
        let rng = StdRng::from_rng(OsRng).unwrap();
        #[cfg(feature = "testing")]
        let rng = if let Ok(seed) = env::var(ENV_VAR_MASP_TEST_SEED)
            .map_err(|e| Error::Other(e.to_string()))
            .and_then(|seed| {
                let exp_str =
                    format!("Env var {ENV_VAR_MASP_TEST_SEED} must be a u64.");
                let parsed_seed: u64 = FromStr::from_str(&seed)
                    .map_err(|_| Error::Other(exp_str))?;
                Ok(parsed_seed)
            }) {
            tracing::warn!(
                "UNSAFE: Using a seed from {ENV_VAR_MASP_TEST_SEED} env var \
                 to build proofs."
            );
            StdRng::seed_from_u64(seed)
        } else {
            rng
        };

        // Now we build up the transaction within this object
        let expiration_height: u32 = match context.tx_builder().expiration {
            Some(expiration) => {
                // Try to match a DateTime expiration with a plausible
                // corresponding block height
                let last_block_height: u64 =
                    crate::rpc::query_block(context.client())
                        .await?
                        .map_or_else(|| 1, |block| u64::from(block.height));
                let current_time = DateTimeUtc::now();
                let delta_time =
                    expiration.0.signed_duration_since(current_time.0);

                let max_expected_time_per_block_key =
                    namada_parameters::storage::get_max_expected_time_per_block_key();
                let max_block_time =
                    crate::rpc::query_storage_value::<_, DurationSecs>(
                        context.client(),
                        &max_expected_time_per_block_key,
                    )
                    .await?;

                let delta_blocks = u32::try_from(
                    delta_time.num_seconds() / max_block_time.0 as i64,
                )
                .map_err(|e| Error::Other(e.to_string()))?;
                u32::try_from(last_block_height)
                    .map_err(|e| Error::Other(e.to_string()))?
                    + delta_blocks
            }
            None => {
                // NOTE: The masp library doesn't support optional expiration so
                // we set the max to mimic a never-expiring tx. We also need to
                // remove 20 which is going to be added back by the builder
                u32::MAX - 20
            }
        };
        let mut builder = Builder::<TestNetwork, _>::new_with_rng(
            NETWORK,
            // NOTE: this is going to add 20 more blocks to the actual
            // expiration but there's no other exposed function that we could
            // use from the masp crate to specify the expiration better
            expiration_height.into(),
            rng,
        );

        // Convert transaction amount into MASP types
        let Some(denom) = query_denom(context.client(), token).await else {
            return Err(TransferErr::General(Error::from(
                QueryError::General(format!("denomination for token {token}")),
            )));
        };
        let (asset_types, masp_amount) = {
            let mut shielded = context.shielded_mut().await;
            // Do the actual conversion to an asset type
            let amount = shielded
                .convert_amount(
                    context.client(),
                    epoch,
                    token,
                    denom,
                    amount.amount(),
                )
                .await?;
            // Make sure to save any decodings of the asset types used so that
            // balance queries involving them are successful
            let _ = shielded.save().await;
            amount
        };

        // If there are shielded inputs
        if let Some(sk) = spending_key {
            // Locate unspent notes that can help us meet the transaction amount
            let (_, unspent_notes, used_convs) = context
                .shielded_mut()
                .await
                .collect_unspent_notes(
                    context,
                    &to_viewing_key(&sk).vk,
                    I128Sum::from_sum(masp_amount),
                    epoch,
                )
                .await?;
            // Commit the notes found to our transaction
            for (diversifier, note, merkle_path) in unspent_notes {
                builder
                    .add_sapling_spend(sk, diversifier, note, merkle_path)
                    .map_err(builder::Error::SaplingBuild)?;
            }
            // Commit the conversion notes used during summation
            for (conv, wit, value) in used_convs.values() {
                if value.is_positive() {
                    builder
                        .add_sapling_convert(
                            conv.clone(),
                            *value as u64,
                            wit.clone(),
                        )
                        .map_err(builder::Error::SaplingBuild)?;
                }
            }
        } else {
            // We add a dummy UTXO to our transaction, but only the source of
            // the parent Transfer object is used to validate fund
            // availability
            let source_enc = source
                .address()
                .ok_or_else(|| {
                    Error::Other(
                        "source address should be transparent".to_string(),
                    )
                })?
                .serialize_to_vec();

            let hash = ripemd::Ripemd160::digest(sha2::Sha256::digest(
                source_enc.as_ref(),
            ));
            let script = TransparentAddress(hash.into());
            for (digit, asset_type) in
                MaspDigitPos::iter().zip(asset_types.iter())
            {
                let amount_part = digit.denominate(&amount.amount());
                // Skip adding an input if its value is 0
                if amount_part != 0 {
                    builder
                        .add_transparent_input(TxOut {
                            asset_type: *asset_type,
                            value: amount_part,
                            address: script,
                        })
                        .map_err(builder::Error::TransparentBuild)?;
                }
            }
        }

        // Anotate the asset type in the value balance with its decoding in
        // order to facilitate cross-epoch computations
        let value_balance = builder.value_balance().map_err(|e| {
            Error::Other(format!("unable to complete value balance: {}", e))
        })?;
        let value_balance = context
            .shielded_mut()
            .await
            .decode_sum(context.client(), value_balance)
            .await;

        // If we are sending to a transparent output, then we will need to embed
        // the transparent target address into the shielded transaction so that
        // it can be signed
        let transparent_target_hash = if payment_address.is_none() {
            let target_enc = target
                .address()
                .ok_or_else(|| {
                    Error::Other(
                        "target address should be transparent".to_string(),
                    )
                })?
                .serialize_to_vec();
            Some(ripemd::Ripemd160::digest(sha2::Sha256::digest(
                target_enc.as_ref(),
            )))
        } else {
            None
        };
        // This indicates how many more assets need to be sent to the receiver
        // in order to satisfy the requested transfer amount.
        let mut rem_amount = amount.amount().raw_amount().0;
        // If we are sending to a shielded address, we may need the outgoing
        // viewing key in the following computations.
        let ovk_opt = spending_key.map(|x| x.expsk.ovk);

        // Now handle the outputs of this transaction
        // Loop through the value balance components and see which
        // ones can be given to the receiver
        for ((asset_type, decoded), val) in value_balance.components() {
            let rem_amount = &mut rem_amount[decoded.position as usize];
            // Only asset types with the correct token can contribute. But
            // there must be a demonstrated need for it.
            if decoded.token == *token
                && decoded.denom == denom
                && decoded.epoch.map_or(true, |vbal_epoch| vbal_epoch <= epoch)
                && *rem_amount > 0
            {
                let val = u128::try_from(*val).expect(
                    "value balance in absence of output descriptors should be \
                     non-negative",
                );
                // We want to take at most the remaining quota for the
                // current denomination to the receiver
                let contr = std::cmp::min(*rem_amount as u128, val) as u64;
                // Make transaction output tied to the current token,
                // denomination, and epoch.
                if let Some(pa) = payment_address {
                    // If there is a shielded output
                    builder
                        .add_sapling_output(
                            ovk_opt,
                            pa.into(),
                            *asset_type,
                            contr,
                            memo.clone(),
                        )
                        .map_err(builder::Error::SaplingBuild)?;
                } else {
                    // If there is a transparent output
                    let hash = transparent_target_hash
                        .expect(
                            "transparent target hash should have been \
                             computed already",
                        )
                        .into();
                    builder
                        .add_transparent_output(
                            &TransparentAddress(hash),
                            *asset_type,
                            contr,
                        )
                        .map_err(builder::Error::TransparentBuild)?;
                }
                // Lower what is required of the remaining contribution
                *rem_amount -= contr;
            }
        }

        // Nothing must remain to be included in output
        if rem_amount != [0; 4] {
            // Convert the shortfall into a I128Sum
            let mut shortfall = I128Sum::zero();
            for (asset_type, val) in asset_types.iter().zip(rem_amount) {
                shortfall += I128Sum::from_pair(*asset_type, val.into())
                    .expect("unable to construct value sum");
            }
            // Return an insufficient ffunds error
            return Result::Err(TransferErr::from(
                builder::Error::InsufficientFunds(shortfall),
            ));
        }

        // Now add outputs representing the change from this payment
        if let Some(sk) = spending_key {
            // Represents the amount of inputs we are short by
            let mut additional = I128Sum::zero();
            for (asset_type, amt) in builder
                .value_balance()
                .map_err(|e| {
                    Error::Other(format!(
                        "unable to complete value balance: {}",
                        e
                    ))
                })?
                .components()
            {
                match amt.cmp(&0) {
                    Ordering::Greater => {
                        // Send the change in this asset type back to the sender
                        builder
                            .add_sapling_output(
                                Some(sk.expsk.ovk),
                                sk.default_address().1,
                                *asset_type,
                                *amt as u64,
                                memo.clone(),
                            )
                            .map_err(builder::Error::SaplingBuild)?;
                    }
                    Ordering::Less => {
                        // Record how much of the current asset type we are
                        // short by
                        additional +=
                            I128Sum::from_nonnegative(*asset_type, -*amt)
                                .map_err(|()| {
                                    Error::Other(format!(
                                        "from non negative conversion: {}",
                                        line!()
                                    ))
                                })?;
                    }
                    Ordering::Equal => {}
                }
            }
            // If we are short by a non-zero amount, then we have insufficient
            // funds
            if !additional.is_zero() {
                return Err(TransferErr::from(
                    builder::Error::InsufficientFunds(additional),
                ));
            }
        }

        let builder_clone = builder.clone().map_builder(WalletMap);
        // Build and return the constructed transaction
        #[cfg(not(feature = "testing"))]
        let prover = context.shielded().await.utils.local_tx_prover();
        #[cfg(feature = "testing")]
        let prover = testing::MockTxProver(std::sync::Mutex::new(OsRng));
        let (masp_tx, metadata) =
            builder.build(&prover, &FeeRule::non_standard(U64Sum::zero()))?;

        if update_ctx {
            // Cache the generated transfer
            let mut shielded_ctx = context.shielded_mut().await;
            shielded_ctx
                .pre_cache_transaction(
                    context, &masp_tx, source, target, token, epoch,
                )
                .await?;
        }

        Ok(Some(ShieldedTransfer {
            builder: builder_clone,
            masp_tx,
            metadata,
            epoch,
        }))
    }

    // Updates the internal state with the data of the newly generated
    // transaction. More specifically invalidate the spent notes and the
    // transparent balances, but do not cache the newly produced output
    // descriptions and therefore the merkle tree
    async fn pre_cache_transaction(
        &mut self,
        context: &impl Namada,
        masp_tx: &Transaction,
        source: &TransferSource,
        target: &TransferTarget,
        token: &Address,
        epoch: Epoch,
    ) -> Result<(), Error> {
        // Need to mock the changed balance keys
        let mut changed_balance_keys = BTreeSet::default();
        match (source.effective_address(), target.effective_address()) {
            // Shielded transactions don't write balance keys
            (MASP, MASP) => (),
            (source, target) => {
                changed_balance_keys.insert(balance_key(token, &source));
                changed_balance_keys.insert(balance_key(token, &target));
            }
        }

        let native_token = query_native_token(context.client()).await?;
        let vks: Vec<_> = context
            .wallet()
            .await
            .get_viewing_keys()
            .values()
            .map(|evk| ExtendedFullViewingKey::from(*evk).fvk.vk)
            .collect();
        let last_witnessed_tx = self.tx_note_map.keys().max();
        // This data will be discarded at the next fetch so we don't need to
        // populate it accurately
        let indexed_tx = last_witnessed_tx.map_or_else(
            || IndexedTx {
                height: BlockHeight::first(),
                index: TxIndex(0),
            },
            |indexed| IndexedTx {
                height: indexed.height,
                index: indexed.index + 1,
            },
        );
        self.sync_status = ContextSyncStatus::Speculative;
        for vk in vks {
            self.vk_heights.entry(vk).or_default();

            self.scan_tx(
                indexed_tx,
                epoch,
                &changed_balance_keys,
                masp_tx,
                &vk,
                native_token.clone(),
            )?;
        }
        // Save the speculative state for future usage
        self.save().await.map_err(|e| Error::Other(e.to_string()))?;

        Ok(())
    }

    /// Obtain the known effects of all accepted shielded and transparent
    /// transactions. If an owner is specified, then restrict the set to only
    /// transactions crediting/debiting the given owner. If token is specified,
    /// then restrict set to only transactions involving the given token.
    pub async fn query_tx_deltas<C: Client + Sync, IO: Io>(
        &mut self,
        client: &C,
        io: &IO,
        query_owner: &Either<BalanceOwner, Vec<Address>>,
        query_token: &Option<Address>,
        viewing_keys: &HashMap<String, ExtendedViewingKey>,
    ) -> Result<
        BTreeMap<IndexedTx, (Epoch, TransferDelta, TransactionDelta)>,
        Error,
    > {
        const TXS_PER_PAGE: u8 = 100;
        let _ = self.load().await;
        let vks = viewing_keys;
        let fvks: Vec<_> = vks
            .values()
            .map(|fvk| ExtendedFullViewingKey::from(*fvk).fvk.vk)
            .collect();
        self.fetch(client, &DefaultLogger::new(io), None, 1, &[], &fvks)
            .await?;
        // Save the update state so that future fetches can be short-circuited
        let _ = self.save().await;
        // Required for filtering out rejected transactions from Tendermint
        // responses
        let block_results = rpc::query_results(client).await?;
        let mut transfers = self.get_tx_deltas().clone();
        // Construct the set of addresses relevant to user's query
        let relevant_addrs = match &query_owner {
            Either::Left(BalanceOwner::Address(owner)) => vec![owner.clone()],
            // MASP objects are dealt with outside of tx_search
            Either::Left(BalanceOwner::FullViewingKey(_viewing_key)) => vec![],
            Either::Left(BalanceOwner::PaymentAddress(_owner)) => vec![],
            // Unspecified owner means all known addresses are considered
            // relevant
            Either::Right(addrs) => addrs.clone(),
        };
        // Find all transactions to or from the relevant address set
        for addr in relevant_addrs {
            for prop in ["transfer.source", "transfer.target"] {
                // Query transactions involving the current address
                let mut tx_query = Query::eq(prop, addr.encode());
                // Elaborate the query if requested by the user
                if let Some(token) = &query_token {
                    tx_query =
                        tx_query.and_eq("transfer.token", token.encode());
                }
                for page in 1.. {
                    let txs = &client
                        .tx_search(
                            tx_query.clone(),
                            true,
                            page,
                            TXS_PER_PAGE,
                            Order::Ascending,
                        )
                        .await
                        .map_err(|e| {
                            Error::from(QueryError::General(format!(
                                "for transaction: {e}"
                            )))
                        })?
                        .txs;
                    for response_tx in txs {
                        let height = BlockHeight(response_tx.height.value());
                        let idx = TxIndex(response_tx.index);
                        // Only process yet unprocessed transactions which have
                        // been accepted by node VPs
                        let should_process = !transfers
                            .contains_key(&IndexedTx { height, index: idx })
                            && block_results[u64::from(height) as usize]
                                .is_accepted(idx.0 as usize);
                        if !should_process {
                            continue;
                        }
                        let tx = Tx::try_from(response_tx.tx.as_ref())
                            .map_err(|e| Error::Other(e.to_string()))?;
                        let mut wrapper = None;
                        let mut transfer = None;
                        extract_payload(tx, &mut wrapper, &mut transfer)?;
                        // Epoch data is not needed for transparent transactions
                        let epoch =
                            wrapper.map(|x| x.epoch).unwrap_or_default();
                        if let Some(transfer) = transfer {
                            // Skip MASP addresses as they are already handled
                            // by ShieldedContext
                            if transfer.source == MASP
                                || transfer.target == MASP
                            {
                                continue;
                            }
                            // Describe how a Transfer simply subtracts from one
                            // account and adds the same to another

                            let delta = TransferDelta::from([(
                                transfer.source.clone(),
                                MaspChange {
                                    asset: transfer.token.clone(),
                                    change: -transfer.amount.amount().change(),
                                },
                            )]);

                            // No shielded accounts are affected by this
                            // Transfer
                            transfers.insert(
                                IndexedTx { height, index: idx },
                                (epoch, delta, TransactionDelta::new()),
                            );
                        }
                    }
                    // An incomplete page signifies no more transactions
                    if (txs.len() as u8) < TXS_PER_PAGE {
                        break;
                    }
                }
            }
        }
        Ok(transfers)
    }

    /// Get the asset type with the given epoch, token, and denomination. If it
    /// does not exist in the protocol, then remove the timestamp. Make sure to
    /// store the derived AssetType so that future decoding is possible.
    pub async fn get_asset_type<C: Client + Sync>(
        &mut self,
        client: &C,
        decoded: &mut AssetData,
    ) -> Result<AssetType, Error> {
        let mut asset_type = decoded.encode().map_err(|_| {
            Error::Other("unable to create asset type".to_string())
        })?;
        if self.decode_asset_type(client, asset_type).await.is_none() {
            // If we fail to decode the epoched asset type, then remove the
            // epoch
            decoded.undate();
            asset_type = decoded.encode().map_err(|_| {
                Error::Other("unable to create asset type".to_string())
            })?;
            self.asset_types.insert(asset_type, decoded.clone());
        }
        Ok(asset_type)
    }

    /// Convert Anoma amount and token type to MASP equivalents
    async fn convert_amount<C: Client + Sync>(
        &mut self,
        client: &C,
        epoch: Epoch,
        token: &Address,
        denom: Denomination,
        val: token::Amount,
    ) -> Result<([AssetType; 4], U64Sum), Error> {
        let mut amount = U64Sum::zero();
        let mut asset_types = Vec::new();
        for position in MaspDigitPos::iter() {
            let mut pre_asset_type = AssetData {
                epoch: Some(epoch),
                token: token.clone(),
                denom,
                position,
            };
            let asset_type =
                self.get_asset_type(client, &mut pre_asset_type).await?;
            // Combine the value and unit into one amount
            amount +=
                U64Sum::from_nonnegative(asset_type, position.denominate(&val))
                    .map_err(|_| {
                        Error::Other("invalid value for amount".to_string())
                    })?;
            asset_types.push(asset_type);
        }
        Ok((
            asset_types
                .try_into()
                .expect("there must be exactly 4 denominations"),
            amount,
        ))
    }
}

/// Extract the payload from the given Tx object
fn extract_payload(
    tx: Tx,
    wrapper: &mut Option<WrapperTx>,
    transfer: &mut Option<Transfer>,
) -> Result<(), Error> {
    *wrapper = tx.header.wrapper();
    let _ = tx.data().map(|signed| {
        Transfer::try_from_slice(&signed[..]).map(|tfer| *transfer = Some(tfer))
    });
    Ok(())
}

// Retrieves all the indexes and tx events at the specified height which refer
// to a valid masp transaction. If an index is given, it filters only the
// transactions with an index equal or greater to the provided one.
async fn get_indexed_masp_events_at_height<C: Client + Sync>(
    client: &C,
    height: BlockHeight,
    first_idx_to_query: Option<TxIndex>,
) -> Result<Option<Vec<(TxIndex, crate::tendermint::abci::Event)>>, Error> {
    let first_idx_to_query = first_idx_to_query.unwrap_or_default();

    Ok(client
        .block_results(height.0 as u32)
        .await
        .map_err(|e| Error::from(QueryError::General(e.to_string())))?
        .end_block_events
        .map(|events| {
            events
                .into_iter()
                .filter_map(|event| {
                    let tx_index =
                        event.attributes.iter().find_map(|attribute| {
                            if attribute.key == "is_valid_masp_tx" {
                                Some(TxIndex(
                                    u32::from_str(&attribute.value).unwrap(),
                                ))
                            } else {
                                None
                            }
                        });

                    match tx_index {
                        Some(idx) => {
                            if idx >= first_idx_to_query {
                                Some((idx, event))
                            } else {
                                None
                            }
                        }
                        None => None,
                    }
                })
                .collect::<Vec<_>>()
        }))
}

enum ExtractShieldedActionArg<'args, C: Client + Sync> {
    Event(&'args crate::tendermint::abci::Event),
    Request((&'args C, BlockHeight, Option<TxIndex>)),
}

// Extract the changed keys and Transaction objects from a masp over ibc message
async fn extract_payload_from_shielded_action<'args, C: Client + Sync>(
    tx_data: &[u8],
    args: ExtractShieldedActionArg<'args, C>,
) -> Result<(BTreeSet<namada_core::storage::Key>, Transaction), Error> {
    let message = namada_ibc::decode_message(tx_data)
        .map_err(|e| Error::Other(e.to_string()))?;

    let result = match message {
        IbcMessage::ShieldedTransfer(msg) => {
            let tx_event = match args {
                ExtractShieldedActionArg::Event(event) => event,
                ExtractShieldedActionArg::Request(_) => {
                    return Err(Error::Other(
                        "Unexpected event request for ShieldedTransfer"
                            .to_string(),
                    ));
                }
            };

            let changed_keys = tx_event
                .attributes
                .iter()
                .find_map(|attribute| {
                    if attribute.key == "inner_tx" {
                        let tx_result =
                            TxResult::from_str(&attribute.value).unwrap();
                        Some(tx_result.changed_keys)
                    } else {
                        None
                    }
                })
                .ok_or_else(|| {
                    Error::Other(
                        "Couldn't find changed keys in the event for the \
                         provided transaction"
                            .to_string(),
                    )
                })?;

            (changed_keys, msg.shielded_transfer.masp_tx)
        }
        IbcMessage::Envelope(_) => {
            let tx_event = match args {
                ExtractShieldedActionArg::Event(event) => {
                    std::borrow::Cow::Borrowed(event)
                }
                ExtractShieldedActionArg::Request((client, height, index)) => {
                    std::borrow::Cow::Owned(
                        get_indexed_masp_events_at_height(
                            client, height, index,
                        )
                        .await?
                        .ok_or_else(|| {
                            Error::Other(format!(
                                "Missing required ibc event at block height {}",
                                height
                            ))
                        })?
                        .first()
                        .ok_or_else(|| {
                            Error::Other(format!(
                                "Missing required ibc event at block height {}",
                                height
                            ))
                        })?
                        .1
                        .to_owned(),
                    )
                }
            };

            tx_event
                .attributes
                .iter()
                .find_map(|attribute| {
                    if attribute.key == "inner_tx" {
                        let tx_result =
                            TxResult::from_str(&attribute.value).unwrap();
                        for ibc_event in &tx_result.ibc_events {
                            let event =
                                namada_core::ibc::get_shielded_transfer(
                                    ibc_event,
                                )
                                .ok()
                                .flatten();
                            if let Some(transfer) = event {
                                return Some((
                                    tx_result.changed_keys,
                                    transfer.masp_tx,
                                ));
                            }
                        }
                        None
                    } else {
                        None
                    }
                })
                .ok_or_else(|| {
                    Error::Other(
                        "Couldn't deserialize masp tx to ibc message envelope"
                            .to_string(),
                    )
                })?
        }
        _ => {
            return Err(Error::Other(
                "Couldn't deserialize masp tx to a valid ibc message"
                    .to_string(),
            ));
        }
    };

    Ok(result)
}

mod tests {
    /// quick and dirty test. will fail on size check
    #[test]
    #[should_panic(expected = "parameter file size is not correct")]
    fn test_wrong_masp_params() {
        use std::io::Write;

        use super::{CONVERT_NAME, OUTPUT_NAME, SPEND_NAME};

        let tempdir = tempfile::tempdir()
            .expect("expected a temp dir")
            .into_path();
        let fake_params_paths =
            [SPEND_NAME, OUTPUT_NAME, CONVERT_NAME].map(|p| tempdir.join(p));
        for path in &fake_params_paths {
            let mut f =
                std::fs::File::create(path).expect("expected a temp file");
            f.write_all(b"fake params")
                .expect("expected a writable temp file");
            f.sync_all()
                .expect("expected a writable temp file (on sync)");
        }

        std::env::set_var(super::ENV_VAR_MASP_PARAMS_DIR, tempdir.as_os_str());
        // should panic here
        masp_proofs::load_parameters(
            &fake_params_paths[0],
            &fake_params_paths[1],
            &fake_params_paths[2],
        );
    }

    /// a more involved test, using dummy parameters with the right
    /// size but the wrong hash.
    #[test]
    #[should_panic(expected = "parameter file is not correct")]
    fn test_wrong_masp_params_hash() {
        use masp_primitives::ff::PrimeField;
        use masp_proofs::bellman::groth16::{
            generate_random_parameters, Parameters,
        };
        use masp_proofs::bellman::{Circuit, ConstraintSystem, SynthesisError};
        use masp_proofs::bls12_381::{Bls12, Scalar};

        use super::{CONVERT_NAME, OUTPUT_NAME, SPEND_NAME};

        struct FakeCircuit<E: PrimeField> {
            x: E,
        }

        impl<E: PrimeField> Circuit<E> for FakeCircuit<E> {
            fn synthesize<CS: ConstraintSystem<E>>(
                self,
                cs: &mut CS,
            ) -> Result<(), SynthesisError> {
                let x = cs.alloc(|| "x", || Ok(self.x)).unwrap();
                cs.enforce(
                    || {
                        "this is an extra long constraint name so that rustfmt \
                         is ok with wrapping the params of enforce()"
                    },
                    |lc| lc + x,
                    |lc| lc + x,
                    |lc| lc + x,
                );
                Ok(())
            }
        }

        let dummy_circuit = FakeCircuit { x: Scalar::zero() };
        let mut rng = rand::thread_rng();
        let fake_params: Parameters<Bls12> =
            generate_random_parameters(dummy_circuit, &mut rng)
                .expect("expected to generate fake params");

        let tempdir = tempfile::tempdir()
            .expect("expected a temp dir")
            .into_path();
        // TODO: get masp to export these consts
        let fake_params_paths = [
            (SPEND_NAME, 49848572u64),
            (OUTPUT_NAME, 16398620u64),
            (CONVERT_NAME, 22570940u64),
        ]
        .map(|(p, s)| (tempdir.join(p), s));
        for (path, size) in &fake_params_paths {
            let mut f =
                std::fs::File::create(path).expect("expected a temp file");
            fake_params
                .write(&mut f)
                .expect("expected a writable temp file");
            // the dummy circuit has one constraint, and therefore its
            // params should always be smaller than the large masp
            // circuit params. so this truncate extends the file, and
            // extra bytes at the end do not make it invalid.
            f.set_len(*size)
                .expect("expected to truncate the temp file");
            f.sync_all()
                .expect("expected a writable temp file (on sync)");
        }

        std::env::set_var(super::ENV_VAR_MASP_PARAMS_DIR, tempdir.as_os_str());
        // should panic here
        masp_proofs::load_parameters(
            &fake_params_paths[0].0,
            &fake_params_paths[1].0,
            &fake_params_paths[2].0,
        );
    }
}

#[cfg(any(test, feature = "testing"))]
/// Tests and strategies for transactions
pub mod testing {
    use std::ops::AddAssign;
    use std::sync::Mutex;

    use bls12_381::{G1Affine, G2Affine};
    use masp_primitives::consensus::testing::arb_height;
    use masp_primitives::constants::SPENDING_KEY_GENERATOR;
    use masp_primitives::ff::Field;
    use masp_primitives::sapling::prover::TxProver;
    use masp_primitives::sapling::redjubjub::Signature;
    use masp_primitives::sapling::{ProofGenerationKey, Rseed};
    use masp_primitives::transaction::components::GROTH_PROOF_SIZE;
    use masp_proofs::bellman::groth16::Proof;
    use proptest::prelude::*;
    use proptest::sample::SizeRange;
    use proptest::test_runner::TestRng;
    use proptest::{collection, option, prop_compose};

    use super::*;
    use crate::address::testing::arb_address;
    use crate::masp_primitives::consensus::BranchId;
    use crate::masp_primitives::constants::VALUE_COMMITMENT_RANDOMNESS_GENERATOR;
    use crate::masp_primitives::merkle_tree::FrozenCommitmentTree;
    use crate::masp_primitives::sapling::keys::OutgoingViewingKey;
    use crate::masp_primitives::sapling::redjubjub::PrivateKey;
    use crate::masp_primitives::transaction::components::transparent::testing::arb_transparent_address;
    use crate::masp_proofs::sapling::SaplingVerificationContextInner;
    use crate::storage::testing::arb_epoch;
    use crate::token::testing::arb_denomination;

    /// A context object for verifying the Sapling components of a single Zcash
    /// transaction. Same as SaplingVerificationContext, but always assumes the
    /// proofs to be valid.
    pub struct MockSaplingVerificationContext {
        inner: SaplingVerificationContextInner,
        zip216_enabled: bool,
    }

    impl MockSaplingVerificationContext {
        /// Construct a new context to be used with a single transaction.
        pub fn new(zip216_enabled: bool) -> Self {
            MockSaplingVerificationContext {
                inner: SaplingVerificationContextInner::new(),
                zip216_enabled,
            }
        }

        /// Perform consensus checks on a Sapling SpendDescription, while
        /// accumulating its value commitment inside the context for later use.
        #[allow(clippy::too_many_arguments)]
        pub fn check_spend(
            &mut self,
            cv: jubjub::ExtendedPoint,
            anchor: bls12_381::Scalar,
            nullifier: &[u8; 32],
            rk: PublicKey,
            sighash_value: &[u8; 32],
            spend_auth_sig: Signature,
            zkproof: Proof<Bls12>,
            _verifying_key: &PreparedVerifyingKey<Bls12>,
        ) -> bool {
            let zip216_enabled = true;
            self.inner.check_spend(
                cv,
                anchor,
                nullifier,
                rk,
                sighash_value,
                spend_auth_sig,
                zkproof,
                &mut (),
                |_, rk, msg, spend_auth_sig| {
                    rk.verify_with_zip216(
                        &msg,
                        &spend_auth_sig,
                        SPENDING_KEY_GENERATOR,
                        zip216_enabled,
                    )
                },
                |_, _proof, _public_inputs| true,
            )
        }

        /// Perform consensus checks on a Sapling SpendDescription, while
        /// accumulating its value commitment inside the context for later use.
        #[allow(clippy::too_many_arguments)]
        pub fn check_convert(
            &mut self,
            cv: jubjub::ExtendedPoint,
            anchor: bls12_381::Scalar,
            zkproof: Proof<Bls12>,
            _verifying_key: &PreparedVerifyingKey<Bls12>,
        ) -> bool {
            self.inner.check_convert(
                cv,
                anchor,
                zkproof,
                &mut (),
                |_, _proof, _public_inputs| true,
            )
        }

        /// Perform consensus checks on a Sapling OutputDescription, while
        /// accumulating its value commitment inside the context for later use.
        pub fn check_output(
            &mut self,
            cv: jubjub::ExtendedPoint,
            cmu: bls12_381::Scalar,
            epk: jubjub::ExtendedPoint,
            zkproof: Proof<Bls12>,
            _verifying_key: &PreparedVerifyingKey<Bls12>,
        ) -> bool {
            self.inner.check_output(
                cv,
                cmu,
                epk,
                zkproof,
                |_proof, _public_inputs| true,
            )
        }

        /// Perform consensus checks on the valueBalance and bindingSig parts of
        /// a Sapling transaction. All SpendDescriptions and
        /// OutputDescriptions must have been checked before calling
        /// this function.
        pub fn final_check(
            &self,
            value_balance: I128Sum,
            sighash_value: &[u8; 32],
            binding_sig: Signature,
        ) -> bool {
            self.inner.final_check(
                value_balance,
                sighash_value,
                binding_sig,
                |bvk, msg, binding_sig| {
                    bvk.verify_with_zip216(
                        &msg,
                        &binding_sig,
                        VALUE_COMMITMENT_RANDOMNESS_GENERATOR,
                        self.zip216_enabled,
                    )
                },
            )
        }
    }

    // This function computes `value` in the exponent of the value commitment
    // base
    fn masp_compute_value_balance(
        asset_type: AssetType,
        value: i128,
    ) -> Option<jubjub::ExtendedPoint> {
        // Compute the absolute value (failing if -i128::MAX is
        // the value)
        let abs = match value.checked_abs() {
            Some(a) => a as u128,
            None => return None,
        };

        // Is it negative? We'll have to negate later if so.
        let is_negative = value.is_negative();

        // Compute it in the exponent
        let mut abs_bytes = [0u8; 32];
        abs_bytes[0..16].copy_from_slice(&abs.to_le_bytes());
        let mut value_balance = asset_type.value_commitment_generator()
            * jubjub::Fr::from_bytes(&abs_bytes).unwrap();

        // Negate if necessary
        if is_negative {
            value_balance = -value_balance;
        }

        // Convert to unknown order point
        Some(value_balance.into())
    }

    // A context object for creating the Sapling components of a Zcash
    // transaction.
    pub struct SaplingProvingContext {
        bsk: jubjub::Fr,
        // (sum of the Spend value commitments) - (sum of the Output value
        // commitments)
        cv_sum: jubjub::ExtendedPoint,
    }

    // An implementation of TxProver that does everything except generating
    // valid zero-knowledge proofs. Uses the supplied source of randomness to
    // carry out its operations.
    pub struct MockTxProver<R: RngCore>(pub Mutex<R>);

    impl<R: RngCore> TxProver for MockTxProver<R> {
        type SaplingProvingContext = SaplingProvingContext;

        fn new_sapling_proving_context(&self) -> Self::SaplingProvingContext {
            SaplingProvingContext {
                bsk: jubjub::Fr::zero(),
                cv_sum: jubjub::ExtendedPoint::identity(),
            }
        }

        fn spend_proof(
            &self,
            ctx: &mut Self::SaplingProvingContext,
            proof_generation_key: ProofGenerationKey,
            _diversifier: Diversifier,
            _rseed: Rseed,
            ar: jubjub::Fr,
            asset_type: AssetType,
            value: u64,
            _anchor: bls12_381::Scalar,
            _merkle_path: MerklePath<Node>,
        ) -> Result<
            ([u8; GROTH_PROOF_SIZE], jubjub::ExtendedPoint, PublicKey),
            (),
        > {
            // Initialize secure RNG
            let mut rng = self.0.lock().unwrap();

            // We create the randomness of the value commitment
            let rcv = jubjub::Fr::random(&mut *rng);

            // Accumulate the value commitment randomness in the context
            {
                let mut tmp = rcv;
                tmp.add_assign(&ctx.bsk);

                // Update the context
                ctx.bsk = tmp;
            }

            // Construct the value commitment
            let value_commitment = asset_type.value_commitment(value, rcv);

            // This is the result of the re-randomization, we compute it for the
            // caller
            let rk = PublicKey(proof_generation_key.ak.into())
                .randomize(ar, SPENDING_KEY_GENERATOR);

            // Compute value commitment
            let value_commitment: jubjub::ExtendedPoint =
                value_commitment.commitment().into();

            // Accumulate the value commitment in the context
            ctx.cv_sum += value_commitment;

            let mut zkproof = [0u8; GROTH_PROOF_SIZE];
            let proof = Proof::<Bls12> {
                a: G1Affine::generator(),
                b: G2Affine::generator(),
                c: G1Affine::generator(),
            };
            proof
                .write(&mut zkproof[..])
                .expect("should be able to serialize a proof");
            Ok((zkproof, value_commitment, rk))
        }

        fn output_proof(
            &self,
            ctx: &mut Self::SaplingProvingContext,
            _esk: jubjub::Fr,
            _payment_address: masp_primitives::sapling::PaymentAddress,
            _rcm: jubjub::Fr,
            asset_type: AssetType,
            value: u64,
        ) -> ([u8; GROTH_PROOF_SIZE], jubjub::ExtendedPoint) {
            // Initialize secure RNG
            let mut rng = self.0.lock().unwrap();

            // We construct ephemeral randomness for the value commitment. This
            // randomness is not given back to the caller, but the synthetic
            // blinding factor `bsk` is accumulated in the context.
            let rcv = jubjub::Fr::random(&mut *rng);

            // Accumulate the value commitment randomness in the context
            {
                let mut tmp = rcv.neg(); // Outputs subtract from the total.
                tmp.add_assign(&ctx.bsk);

                // Update the context
                ctx.bsk = tmp;
            }

            // Construct the value commitment for the proof instance
            let value_commitment = asset_type.value_commitment(value, rcv);

            // Compute the actual value commitment
            let value_commitment_point: jubjub::ExtendedPoint =
                value_commitment.commitment().into();

            // Accumulate the value commitment in the context. We do this to
            // check internal consistency.
            ctx.cv_sum -= value_commitment_point; // Outputs subtract from the total.

            let mut zkproof = [0u8; GROTH_PROOF_SIZE];
            let proof = Proof::<Bls12> {
                a: G1Affine::generator(),
                b: G2Affine::generator(),
                c: G1Affine::generator(),
            };
            proof
                .write(&mut zkproof[..])
                .expect("should be able to serialize a proof");

            (zkproof, value_commitment_point)
        }

        fn convert_proof(
            &self,
            ctx: &mut Self::SaplingProvingContext,
            allowed_conversion: AllowedConversion,
            value: u64,
            _anchor: bls12_381::Scalar,
            _merkle_path: MerklePath<Node>,
        ) -> Result<([u8; GROTH_PROOF_SIZE], jubjub::ExtendedPoint), ()>
        {
            // Initialize secure RNG
            let mut rng = self.0.lock().unwrap();

            // We create the randomness of the value commitment
            let rcv = jubjub::Fr::random(&mut *rng);

            // Accumulate the value commitment randomness in the context
            {
                let mut tmp = rcv;
                tmp.add_assign(&ctx.bsk);

                // Update the context
                ctx.bsk = tmp;
            }

            // Construct the value commitment
            let value_commitment =
                allowed_conversion.value_commitment(value, rcv);

            // Compute value commitment
            let value_commitment: jubjub::ExtendedPoint =
                value_commitment.commitment().into();

            // Accumulate the value commitment in the context
            ctx.cv_sum += value_commitment;

            let mut zkproof = [0u8; GROTH_PROOF_SIZE];
            let proof = Proof::<Bls12> {
                a: G1Affine::generator(),
                b: G2Affine::generator(),
                c: G1Affine::generator(),
            };
            proof
                .write(&mut zkproof[..])
                .expect("should be able to serialize a proof");

            Ok((zkproof, value_commitment))
        }

        fn binding_sig(
            &self,
            ctx: &mut Self::SaplingProvingContext,
            assets_and_values: &I128Sum,
            sighash: &[u8; 32],
        ) -> Result<Signature, ()> {
            // Initialize secure RNG
            let mut rng = self.0.lock().unwrap();

            // Grab the current `bsk` from the context
            let bsk = PrivateKey(ctx.bsk);

            // Grab the `bvk` using DerivePublic.
            let bvk = PublicKey::from_private(
                &bsk,
                VALUE_COMMITMENT_RANDOMNESS_GENERATOR,
            );

            // In order to check internal consistency, let's use the accumulated
            // value commitments (as the verifier would) and apply
            // value_balance to compare against our derived bvk.
            {
                let final_bvk = assets_and_values
                    .components()
                    .map(|(asset_type, value_balance)| {
                        // Compute value balance for each asset
                        // Error for bad value balances (-INT128_MAX value)
                        masp_compute_value_balance(*asset_type, *value_balance)
                    })
                    .try_fold(ctx.cv_sum, |tmp, value_balance| {
                        // Compute cv_sum minus sum of all value balances
                        Result::<_, ()>::Ok(tmp - value_balance.ok_or(())?)
                    })?;

                // The result should be the same, unless the provided
                // valueBalance is wrong.
                if bvk.0 != final_bvk {
                    return Err(());
                }
            }

            // Construct signature message
            let mut data_to_be_signed = [0u8; 64];
            data_to_be_signed[0..32].copy_from_slice(&bvk.0.to_bytes());
            data_to_be_signed[32..64].copy_from_slice(&sighash[..]);

            // Sign
            Ok(bsk.sign(
                &data_to_be_signed,
                &mut *rng,
                VALUE_COMMITMENT_RANDOMNESS_GENERATOR,
            ))
        }
    }

    #[derive(Debug, Clone)]
    // Adapts a CSPRNG from a PRNG for proptesting
    pub struct TestCsprng<R: RngCore>(R);

    impl<R: RngCore> CryptoRng for TestCsprng<R> {}

    impl<R: RngCore> RngCore for TestCsprng<R> {
        fn next_u32(&mut self) -> u32 {
            self.0.next_u32()
        }

        fn next_u64(&mut self) -> u64 {
            self.0.next_u64()
        }

        fn fill_bytes(&mut self, dest: &mut [u8]) {
            self.0.fill_bytes(dest)
        }

        fn try_fill_bytes(
            &mut self,
            dest: &mut [u8],
        ) -> Result<(), rand::Error> {
            self.0.try_fill_bytes(dest)
        }
    }

    prop_compose! {
        // Expose a random number generator
        pub fn arb_rng()(rng in Just(()).prop_perturb(|(), rng| rng)) -> TestRng {
            rng
        }
    }

    prop_compose! {
        // Generate an arbitrary output description with the given value
        pub fn arb_output_description(
            asset_type: AssetType,
            value: u64,
        )(
            mut rng in arb_rng().prop_map(TestCsprng),
        ) -> (Option<OutgoingViewingKey>, masp_primitives::sapling::PaymentAddress, AssetType, u64, MemoBytes) {
            let mut spending_key_seed = [0; 32];
            rng.fill_bytes(&mut spending_key_seed);
            let spending_key = masp_primitives::zip32::ExtendedSpendingKey::master(spending_key_seed.as_ref());

            let viewing_key = ExtendedFullViewingKey::from(&spending_key).fvk.vk;
            let (div, _g_d) = find_valid_diversifier(&mut rng);
            let payment_addr = viewing_key
                .to_payment_address(div)
                .expect("a PaymentAddress");

            (None, payment_addr, asset_type, value, MemoBytes::empty())
        }
    }

    prop_compose! {
        // Generate an arbitrary spend description with the given value
        pub fn arb_spend_description(
            asset_type: AssetType,
            value: u64,
        )(
            address in arb_transparent_address(),
            expiration_height in arb_height(BranchId::MASP, &TestNetwork),
            mut rng in arb_rng().prop_map(TestCsprng),
            prover_rng in arb_rng().prop_map(TestCsprng),
        ) -> (ExtendedSpendingKey, Diversifier, Note, Node) {
            let mut spending_key_seed = [0; 32];
            rng.fill_bytes(&mut spending_key_seed);
            let spending_key = masp_primitives::zip32::ExtendedSpendingKey::master(spending_key_seed.as_ref());

            let viewing_key = ExtendedFullViewingKey::from(&spending_key).fvk.vk;
            let (div, _g_d) = find_valid_diversifier(&mut rng);
            let payment_addr = viewing_key
                .to_payment_address(div)
                .expect("a PaymentAddress");

            let mut builder = Builder::<TestNetwork, _>::new_with_rng(
                NETWORK,
                // NOTE: this is going to add 20 more blocks to the actual
                // expiration but there's no other exposed function that we could
                // use from the masp crate to specify the expiration better
                expiration_height.unwrap(),
                rng,
            );
            // Add a transparent input to support our desired shielded output
            builder.add_transparent_input(TxOut { asset_type, value, address }).unwrap();
            // Finally add the shielded output that we need
            builder.add_sapling_output(None, payment_addr, asset_type, value, MemoBytes::empty()).unwrap();
            // Build a transaction in order to get its shielded outputs
            let (transaction, metadata) = builder.build(
                &MockTxProver(Mutex::new(prover_rng)),
                &FeeRule::non_standard(U64Sum::zero()),
            ).unwrap();
            // Extract the shielded output from the transaction
            let shielded_output = &transaction
                .sapling_bundle()
                .unwrap()
                .shielded_outputs[metadata.output_index(0).unwrap()];

            // Let's now decrypt the constructed notes
            let (note, pa, _memo) = try_sapling_note_decryption::<_, OutputDescription<<<Authorized as Authorization>::SaplingAuth as masp_primitives::transaction::components::sapling::Authorization>::Proof>>(
                &NETWORK,
                1.into(),
                &PreparedIncomingViewingKey::new(&viewing_key.ivk()),
                shielded_output,
            ).unwrap();
            assert_eq!(payment_addr, pa);
            // Make a path to out new note
            let node = Node::new(shielded_output.cmu.to_repr());
            (spending_key, div, note, node)
        }
    }

    prop_compose! {
        // Generate an arbitrary MASP denomination
        pub fn arb_masp_digit_pos()(denom in 0..4u8) -> MaspDigitPos {
            MaspDigitPos::from(denom)
        }
    }

    // Maximum value for a note partition
    const MAX_MONEY: u64 = 100;
    // Maximum number of partitions for a note
    const MAX_SPLITS: usize = 3;

    prop_compose! {
        // Arbitrarily partition the given vector of integers into sets and sum
        // them
        pub fn arb_partition(values: Vec<u64>)(buckets in ((!values.is_empty()) as usize)..=values.len())(
            values in Just(values.clone()),
            assigns in collection::vec(0..buckets, values.len()),
            buckets in Just(buckets),
        ) -> Vec<u64> {
            let mut buckets = vec![0; buckets];
            for (bucket, value) in assigns.iter().zip(values) {
                buckets[*bucket] += value;
            }
            buckets
        }
    }

    prop_compose! {
        // Generate arbitrary spend descriptions with the given asset type
        // partitioning the given values
        pub fn arb_spend_descriptions(
            asset: AssetData,
            values: Vec<u64>,
        )(partition in arb_partition(values))(
            spend_description in partition
                .iter()
                .map(|value| arb_spend_description(
                    encode_asset_type(
                        asset.token.clone(),
                        asset.denom,
                        asset.position,
                        asset.epoch,
                    ).unwrap(),
                    *value,
                )).collect::<Vec<_>>()
        ) -> Vec<(ExtendedSpendingKey, Diversifier, Note, Node)> {
            spend_description
        }
    }

    prop_compose! {
        // Generate arbitrary output descriptions with the given asset type
        // partitioning the given values
        pub fn arb_output_descriptions(
            asset: AssetData,
            values: Vec<u64>,
        )(partition in arb_partition(values))(
            output_description in partition
                .iter()
                .map(|value| arb_output_description(
                    encode_asset_type(
                        asset.token.clone(),
                        asset.denom,
                        asset.position,
                        asset.epoch,
                    ).unwrap(),
                    *value,
                )).collect::<Vec<_>>()
        ) -> Vec<(Option<OutgoingViewingKey>, masp_primitives::sapling::PaymentAddress, AssetType, u64, MemoBytes)> {
            output_description
        }
    }

    prop_compose! {
        // Generate arbitrary spend descriptions with the given asset type
        // partitioning the given values
        pub fn arb_txouts(
            asset: AssetData,
            values: Vec<u64>,
            address: TransparentAddress,
        )(
            partition in arb_partition(values),
        ) -> Vec<TxOut> {
            partition
                .iter()
                .map(|value| TxOut {
                    asset_type: encode_asset_type(
                        asset.token.clone(),
                        asset.denom,
                        asset.position,
                        asset.epoch,
                    ).unwrap(),
                    value: *value,
                    address,
                }).collect::<Vec<_>>()
        }
    }

    prop_compose! {
        // Generate an arbitrary shielded MASP transaction builder
        pub fn arb_shielded_builder(asset_range: impl Into<SizeRange>)(
            assets in collection::hash_map(
                arb_pre_asset_type(),
                collection::vec(..MAX_MONEY, ..MAX_SPLITS),
                asset_range,
            ),
        )(
            expiration_height in arb_height(BranchId::MASP, &TestNetwork),
            rng in arb_rng().prop_map(TestCsprng),
            spend_descriptions in assets
                .iter()
                .map(|(asset, values)| arb_spend_descriptions(asset.clone(), values.clone()))
                .collect::<Vec<_>>(),
            output_descriptions in assets
                .iter()
                .map(|(asset, values)| arb_output_descriptions(asset.clone(), values.clone()))
                .collect::<Vec<_>>(),
            assets in Just(assets),
        ) -> (
            Builder::<TestNetwork, TestCsprng<TestRng>>,
            HashMap<AssetData, u64>,
        ) {
            let mut builder = Builder::<TestNetwork, _>::new_with_rng(
                NETWORK,
                // NOTE: this is going to add 20 more blocks to the actual
                // expiration but there's no other exposed function that we could
                // use from the masp crate to specify the expiration better
                expiration_height.unwrap(),
                rng,
            );
            let mut leaves = Vec::new();
            // First construct a Merkle tree containing all notes to be used
            for (_esk, _div, _note, node) in spend_descriptions.iter().flatten() {
                leaves.push(*node);
            }
            let tree = FrozenCommitmentTree::new(&leaves);
            // Then use the notes knowing that they all have the same anchor
            for (idx, (esk, div, note, _node)) in spend_descriptions.iter().flatten().enumerate() {
                builder.add_sapling_spend(*esk, *div, *note, tree.path(idx)).unwrap();
            }
            for (ovk, payment_addr, asset_type, value, memo) in output_descriptions.into_iter().flatten() {
                builder.add_sapling_output(ovk, payment_addr, asset_type, value, memo).unwrap();
            }
            (builder, assets.into_iter().map(|(k, v)| (k, v.iter().sum())).collect())
        }
    }

    prop_compose! {
        // Generate an arbitrary pre-asset type
        pub fn arb_pre_asset_type()(
            token in arb_address(),
            denom in arb_denomination(),
            position in arb_masp_digit_pos(),
            epoch in option::of(arb_epoch()),
        ) -> AssetData {
            AssetData {
                token,
                denom,
                position,
                epoch,
            }
        }
    }

    prop_compose! {
        // Generate an arbitrary shielding MASP transaction builder
        pub fn arb_shielding_builder(
            source: TransparentAddress,
            asset_range: impl Into<SizeRange>,
        )(
            assets in collection::hash_map(
                arb_pre_asset_type(),
                collection::vec(..MAX_MONEY, ..MAX_SPLITS),
                asset_range,
            ),
        )(
            expiration_height in arb_height(BranchId::MASP, &TestNetwork),
            rng in arb_rng().prop_map(TestCsprng),
            txins in assets
                .iter()
                .map(|(asset, values)| arb_txouts(asset.clone(), values.clone(), source))
                .collect::<Vec<_>>(),
            output_descriptions in assets
                .iter()
                .map(|(asset, values)| arb_output_descriptions(asset.clone(), values.clone()))
                .collect::<Vec<_>>(),
            assets in Just(assets),
        ) -> (
            Builder::<TestNetwork, TestCsprng<TestRng>>,
            HashMap<AssetData, u64>,
        ) {
            let mut builder = Builder::<TestNetwork, _>::new_with_rng(
                NETWORK,
                // NOTE: this is going to add 20 more blocks to the actual
                // expiration but there's no other exposed function that we could
                // use from the masp crate to specify the expiration better
                expiration_height.unwrap(),
                rng,
            );
            for txin in txins.into_iter().flatten() {
                builder.add_transparent_input(txin).unwrap();
            }
            for (ovk, payment_addr, asset_type, value, memo) in output_descriptions.into_iter().flatten() {
                builder.add_sapling_output(ovk, payment_addr, asset_type, value, memo).unwrap();
            }
            (builder, assets.into_iter().map(|(k, v)| (k, v.iter().sum())).collect())
        }
    }

    prop_compose! {
        // Generate an arbitrary deshielding MASP transaction builder
        pub fn arb_deshielding_builder(
            target: TransparentAddress,
            asset_range: impl Into<SizeRange>,
        )(
            assets in collection::hash_map(
                arb_pre_asset_type(),
                collection::vec(..MAX_MONEY, ..MAX_SPLITS),
                asset_range,
            ),
        )(
            expiration_height in arb_height(BranchId::MASP, &TestNetwork),
            rng in arb_rng().prop_map(TestCsprng),
            spend_descriptions in assets
                .iter()
                .map(|(asset, values)| arb_spend_descriptions(asset.clone(), values.clone()))
                .collect::<Vec<_>>(),
            txouts in assets
                .iter()
                .map(|(asset, values)| arb_txouts(asset.clone(), values.clone(), target))
                .collect::<Vec<_>>(),
            assets in Just(assets),
        ) -> (
            Builder::<TestNetwork, TestCsprng<TestRng>>,
            HashMap<AssetData, u64>,
        ) {
            let mut builder = Builder::<TestNetwork, _>::new_with_rng(
                NETWORK,
                // NOTE: this is going to add 20 more blocks to the actual
                // expiration but there's no other exposed function that we could
                // use from the masp crate to specify the expiration better
                expiration_height.unwrap(),
                rng,
            );
            let mut leaves = Vec::new();
            // First construct a Merkle tree containing all notes to be used
            for (_esk, _div, _note, node) in spend_descriptions.iter().flatten() {
                leaves.push(*node);
            }
            let tree = FrozenCommitmentTree::new(&leaves);
            // Then use the notes knowing that they all have the same anchor
            for (idx, (esk, div, note, _node)) in spend_descriptions.into_iter().flatten().enumerate() {
                builder.add_sapling_spend(esk, div, note, tree.path(idx)).unwrap();
            }
            for txout in txouts.into_iter().flatten() {
                builder.add_transparent_output(&txout.address, txout.asset_type, txout.value).unwrap();
            }
            (builder, assets.into_iter().map(|(k, v)| (k, v.iter().sum())).collect())
        }
    }

    prop_compose! {
        // Generate an arbitrary MASP shielded transfer
        pub fn arb_shielded_transfer(
            asset_range: impl Into<SizeRange>,
        )(asset_range in Just(asset_range.into()))(
            (builder, asset_types) in arb_shielded_builder(asset_range),
            epoch in arb_epoch(),
            rng in arb_rng().prop_map(TestCsprng),
        ) -> (ShieldedTransfer, HashMap<AssetData, u64>) {
            let (masp_tx, metadata) = builder.clone().build(
                &MockTxProver(Mutex::new(rng)),
                &FeeRule::non_standard(U64Sum::zero()),
            ).unwrap();
            (ShieldedTransfer {
                builder: builder.map_builder(WalletMap),
                metadata,
                masp_tx,
                epoch,
            }, asset_types)
        }
    }

    prop_compose! {
        // Generate an arbitrary MASP shielded transfer
        pub fn arb_shielding_transfer(
            source: TransparentAddress,
            asset_range: impl Into<SizeRange>,
        )(asset_range in Just(asset_range.into()))(
            (builder, asset_types) in arb_shielding_builder(
                source,
                asset_range,
            ),
            epoch in arb_epoch(),
            rng in arb_rng().prop_map(TestCsprng),
        ) -> (ShieldedTransfer, HashMap<AssetData, u64>) {
            let (masp_tx, metadata) = builder.clone().build(
                &MockTxProver(Mutex::new(rng)),
                &FeeRule::non_standard(U64Sum::zero()),
            ).unwrap();
            (ShieldedTransfer {
                builder: builder.map_builder(WalletMap),
                metadata,
                masp_tx,
                epoch,
            }, asset_types)
        }
    }

    prop_compose! {
        // Generate an arbitrary MASP shielded transfer
        pub fn arb_deshielding_transfer(
            target: TransparentAddress,
            asset_range: impl Into<SizeRange>,
        )(asset_range in Just(asset_range.into()))(
            (builder, asset_types) in arb_deshielding_builder(
                target,
                asset_range,
            ),
            epoch in arb_epoch(),
            rng in arb_rng().prop_map(TestCsprng),
        ) -> (ShieldedTransfer, HashMap<AssetData, u64>) {
            let (masp_tx, metadata) = builder.clone().build(
                &MockTxProver(Mutex::new(rng)),
                &FeeRule::non_standard(U64Sum::zero()),
            ).unwrap();
            (ShieldedTransfer {
                builder: builder.map_builder(WalletMap),
                metadata,
                masp_tx,
                epoch,
            }, asset_types)
        }
    }
}

#[cfg(feature = "std")]
/// Implementation of MASP functionality depending on a standard filesystem
pub mod fs {
    use std::fs::{File, OpenOptions};
    use std::io::{Read, Write};

    use super::*;

    /// Shielded context file name
    const FILE_NAME: &str = "shielded.dat";
    const TMP_FILE_NAME: &str = "shielded.tmp";
    const SPECULATIVE_FILE_NAME: &str = "speculative_shielded.dat";
    const SPECULATIVE_TMP_FILE_NAME: &str = "speculative_shielded.tmp";

    #[derive(Debug, BorshSerialize, BorshDeserialize, Clone)]
    /// An implementation of ShieldedUtils for standard filesystems
    pub struct FsShieldedUtils {
        #[borsh(skip)]
        context_dir: PathBuf,
    }

    impl FsShieldedUtils {
        /// Initialize a shielded transaction context that identifies notes
        /// decryptable by any viewing key in the given set
        pub fn new(context_dir: PathBuf) -> ShieldedContext<Self> {
            // Make sure that MASP parameters are downloaded to enable MASP
            // transaction building and verification later on
            let params_dir = get_params_dir();
            let spend_path = params_dir.join(SPEND_NAME);
            let convert_path = params_dir.join(CONVERT_NAME);
            let output_path = params_dir.join(OUTPUT_NAME);
            if !(spend_path.exists()
                && convert_path.exists()
                && output_path.exists())
            {
                println!("MASP parameters not present, downloading...");
                masp_proofs::download_masp_parameters(None)
                    .expect("MASP parameters not present or downloadable");
                println!(
                    "MASP parameter download complete, resuming execution..."
                );
            }
            // Finally initialize a shielded context with the supplied directory

            let sync_status =
                if std::fs::read(context_dir.join(SPECULATIVE_FILE_NAME))
                    .is_ok()
                {
                    // Load speculative state
                    ContextSyncStatus::Speculative
                } else {
                    ContextSyncStatus::Confirmed
                };

            let utils = Self { context_dir };
            ShieldedContext {
                utils,
                sync_status,
                ..Default::default()
            }
        }
    }

    impl Default for FsShieldedUtils {
        fn default() -> Self {
            Self {
                context_dir: PathBuf::from(FILE_NAME),
            }
        }
    }

    #[cfg_attr(feature = "async-send", async_trait::async_trait)]
    #[cfg_attr(not(feature = "async-send"), async_trait::async_trait(?Send))]
    impl ShieldedUtils for FsShieldedUtils {
        fn local_tx_prover(&self) -> LocalTxProver {
            if let Ok(params_dir) = env::var(ENV_VAR_MASP_PARAMS_DIR) {
                let params_dir = PathBuf::from(params_dir);
                let spend_path = params_dir.join(SPEND_NAME);
                let convert_path = params_dir.join(CONVERT_NAME);
                let output_path = params_dir.join(OUTPUT_NAME);
                LocalTxProver::new(&spend_path, &output_path, &convert_path)
            } else {
                LocalTxProver::with_default_location()
                    .expect("unable to load MASP Parameters")
            }
        }

        /// Try to load the last saved shielded context from the given context
        /// directory. If this fails, then leave the current context unchanged.
        async fn load<U: ShieldedUtils + MaybeSend>(
            &self,
            ctx: &mut ShieldedContext<U>,
            force_confirmed: bool,
        ) -> std::io::Result<()> {
            // Try to load shielded context from file
            let file_name = if force_confirmed {
                FILE_NAME
            } else {
                match ctx.sync_status {
                    ContextSyncStatus::Confirmed => FILE_NAME,
                    ContextSyncStatus::Speculative => SPECULATIVE_FILE_NAME,
                }
            };
            let mut ctx_file = File::open(self.context_dir.join(file_name))?;
            let mut bytes = Vec::new();
            ctx_file.read_to_end(&mut bytes)?;
            // Fill the supplied context with the deserialized object
            *ctx = ShieldedContext {
                utils: ctx.utils.clone(),
                ..ShieldedContext::<U>::deserialize(&mut &bytes[..])?
            };
            Ok(())
        }

        /// Save this confirmed shielded context into its associated context
        /// directory. At the same time, delete the speculative file if present
        async fn save<U: ShieldedUtils + MaybeSync>(
            &self,
            ctx: &ShieldedContext<U>,
        ) -> std::io::Result<()> {
            // TODO: use mktemp crate?
            let (tmp_file_name, file_name) = match ctx.sync_status {
                ContextSyncStatus::Confirmed => (TMP_FILE_NAME, FILE_NAME),
                ContextSyncStatus::Speculative => {
                    (SPECULATIVE_TMP_FILE_NAME, SPECULATIVE_FILE_NAME)
                }
            };
            let tmp_path = self.context_dir.join(tmp_file_name);
            {
                // First serialize the shielded context into a temporary file.
                // Inability to create this file implies a simultaneuous write
                // is in progress. In this case, immediately
                // fail. This is unproblematic because the data
                // intended to be stored can always be re-fetched
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
            // Atomicity is required to prevent other client instances from
            // reading corrupt data.
            std::fs::rename(tmp_path, self.context_dir.join(file_name))?;

            // Remove the speculative file if present since it's state is
            // overruled by the confirmed one we just saved
            if let ContextSyncStatus::Confirmed = ctx.sync_status {
                let _ = std::fs::remove_file(
                    self.context_dir.join(SPECULATIVE_FILE_NAME),
                );
            }

            Ok(())
        }
    }
}

/// A enum to indicate how to log sync progress depending on
/// whether sync is currently fetch or scanning blocks.
#[derive(Debug, Copy, Clone)]
pub enum ProgressType {
    Fetch,
    Scan,
}

pub trait ProgressLogger<IO: Io> {
    type Fetch: Iterator<Item = u64>;
    type Scan: Iterator<Item = IndexedNoteEntry>;

    fn io(&self) -> &IO;

    fn fetch<I>(&self, items: I) -> Self::Fetch
    where
        I: IntoIterator<Item = u64>;

    fn scan<I>(&self, items: I) -> Self::Scan
    where
        I: IntoIterator<Item = IndexedNoteEntry>;
}

/// The default type for logging sync progress.
#[derive(Debug, Clone)]
pub struct DefaultLogger<'io, IO: Io> {
    io: &'io IO,
}

impl<'io, IO: Io> DefaultLogger<'io, IO> {
    pub fn new(io: &'io IO) -> Self {
        Self { io }
    }
}

impl<'io, IO: Io> ProgressLogger<IO> for DefaultLogger<'io, IO> {
    type Fetch = <Vec<u64> as IntoIterator>::IntoIter;
    type Scan = <Vec<IndexedNoteEntry> as IntoIterator>::IntoIter;

    fn io(&self) -> &IO {
        self.io
    }

    fn fetch<I>(&self, items: I) -> Self::Fetch
    where
        I: IntoIterator<Item = u64>,
    {
        let items: Vec<_> = items.into_iter().collect();
        items.into_iter()
    }

    fn scan<I>(&self, items: I) -> Self::Scan
    where
        I: IntoIterator<Item = IndexedNoteEntry>,
    {
        let items: Vec<_> = items.into_iter().collect();
        items.into_iter()
    }
}
