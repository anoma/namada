//! MASP verification wrappers.

#[cfg(test)]
mod test_utils;
pub mod utils;

use std::cmp::Ordering;
use std::collections::{btree_map, BTreeMap, BTreeSet};
use std::env;
use std::fmt::Debug;
use std::io::{Read, Write};
use std::ops::Deref;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use borsh::{BorshDeserialize, BorshSerialize};
use borsh_ext::BorshSerializeExt;
use lazy_static::lazy_static;
use masp_primitives::asset_type::AssetType;
#[cfg(feature = "mainnet")]
use masp_primitives::consensus::MainNetwork as Network;
#[cfg(not(feature = "mainnet"))]
use masp_primitives::consensus::TestNetwork as Network;
use masp_primitives::convert::AllowedConversion;
use masp_primitives::ff::PrimeField;
use masp_primitives::memo::MemoBytes;
use masp_primitives::merkle_tree::{
    CommitmentTree, IncrementalWitness, MerklePath,
};
use masp_primitives::sapling::keys::FullViewingKey;
use masp_primitives::sapling::note_encryption::*;
use masp_primitives::sapling::{
    Diversifier, Node, Note, Nullifier, ViewingKey,
};
use masp_primitives::transaction::builder::{self, *};
use masp_primitives::transaction::components::sapling::builder::{
    RngBuildParams, SaplingMetadata,
};
use masp_primitives::transaction::components::sapling::{
    Authorized as SaplingAuthorized, Bundle as SaplingBundle,
};
use masp_primitives::transaction::components::transparent::builder::TransparentBuilder;
use masp_primitives::transaction::components::{
    I128Sum, OutputDescription, TxOut, U64Sum, ValueSum,
};
use masp_primitives::transaction::fees::fixed::FeeRule;
use masp_primitives::transaction::sighash::{signature_hash, SignableInput};
use masp_primitives::transaction::txid::TxIdDigester;
use masp_primitives::transaction::{
    Authorization, Authorized, Transaction, TransactionData,
    TransparentAddress, Unauthorized,
};
use masp_primitives::zip32::{ExtendedFullViewingKey, ExtendedSpendingKey};
use masp_proofs::bellman::groth16::VerifyingKey;
use masp_proofs::bls12_381::Bls12;
use masp_proofs::prover::LocalTxProver;
use masp_proofs::sapling::BatchValidator;
use namada_core::address::Address;
use namada_core::collections::{HashMap, HashSet};
use namada_core::dec::Dec;
pub use namada_core::masp::{
    encode_asset_type, AssetData, BalanceOwner, ExtendedViewingKey,
    PaymentAddress, TransferSource, TransferTarget,
};
use namada_core::masp::{MaspEpoch, MaspTxRefs};
use namada_core::storage::{BlockHeight, TxIndex};
use namada_core::time::{DateTimeUtc, DurationSecs};
use namada_core::uint::Uint;
use namada_events::extend::{
    MaspTxBatchRefs as MaspTxBatchRefsAttr,
    MaspTxBlockIndex as MaspTxBlockIndexAttr, ReadFromEventAttributes,
};
use namada_macros::BorshDeserializer;
#[cfg(feature = "migrations")]
use namada_migrations::*;
use namada_state::StorageError;
use namada_token::{self as token, Denomination, MaspDigitPos};
use namada_tx::{IndexedTx, Tx};
use rand::rngs::StdRng;
use rand_core::{CryptoRng, OsRng, RngCore, SeedableRng};
use ripemd::Digest as RipemdDigest;
use sha2::Digest;
use smooth_operator::checked;
use thiserror::Error;

use crate::control_flow::ShutdownSignal;
use crate::error::{Error, QueryError};
use crate::io::Io;
use crate::masp::utils::{
    fetch_channel, FetchQueueSender, MaspClient, ProgressTracker, RetryStrategy,
};
use crate::queries::Client;
use crate::rpc::{query_block, query_conversion, query_denom};
use crate::{
    control_flow, display_line, edisplay_line, rpc, MaybeSend, MaybeSync,
    Namada,
};

/// Env var to point to a dir with MASP parameters. When not specified,
/// the default OS specific path is used.
pub const ENV_VAR_MASP_PARAMS_DIR: &str = "NAMADA_MASP_PARAMS_DIR";

/// Randomness seed for MASP integration tests to build proofs with
/// deterministic rng.
pub const ENV_VAR_MASP_TEST_SEED: &str = "NAMADA_MASP_TEST_SEED";

/// The network to use for MASP
const NETWORK: Network = Network;

// TODO these could be exported from masp_proof crate
/// Spend circuit name
pub const SPEND_NAME: &str = "masp-spend.params";
/// Output circuit name
pub const OUTPUT_NAME: &str = "masp-output.params";
/// Convert circuit name
pub const CONVERT_NAME: &str = "masp-convert.params";

/// Type alias for convenience and profit
pub type IndexedNoteData = BTreeMap<IndexedTx, Vec<Transaction>>;

/// Type alias for the entries of [`IndexedNoteData`] iterators
pub type IndexedNoteEntry = (IndexedTx, Vec<Transaction>);

/// Shielded transfer
#[derive(Clone, Debug, BorshSerialize, BorshDeserialize, BorshDeserializer)]
pub struct ShieldedTransfer {
    /// Shielded transfer builder
    pub builder: Builder<(), ExtendedFullViewingKey, ()>,
    /// MASP transaction
    pub masp_tx: Transaction,
    /// Metadata
    pub metadata: SaplingMetadata,
    /// Epoch in which the transaction was created
    pub epoch: MaspEpoch,
}

/// Shielded pool data for a token
#[allow(missing_docs)]
#[derive(Debug, BorshSerialize, BorshDeserialize, BorshDeserializer)]
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
    pub spend_vk: VerifyingKey<Bls12>,
    /// convert verifying key
    pub convert_vk: VerifyingKey<Bls12>,
    /// output verifying key
    pub output_vk: VerifyingKey<Bls12>,
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
            spend_vk: params.spend_params.vk,
            convert_vk: params.convert_params.vk,
            output_vk: params.output_params.vk
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

/// Represents an authorization where the Sapling bundle is authorized and the
/// transparent bundle is unauthorized.
pub struct PartialAuthorized;

impl Authorization for PartialAuthorized {
    type SaplingAuth = <Authorized as Authorization>::SaplingAuth;
    type TransparentAuth = <Unauthorized as Authorization>::TransparentAuth;
}

/// Partially deauthorize the transparent bundle
pub fn partial_deauthorize(
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
pub fn verify_shielded_tx<F>(
    transaction: &Transaction,
    consume_verify_gas: F,
) -> Result<(), StorageError>
where
    F: Fn(u64) -> std::result::Result<(), StorageError>,
{
    tracing::debug!("entered verify_shielded_tx()");

    let sapling_bundle = if let Some(bundle) = transaction.sapling_bundle() {
        bundle
    } else {
        return Err(StorageError::SimpleMessage("no sapling bundle"));
    };
    let tx_data = transaction.deref();

    // Partially deauthorize the transparent bundle
    let unauth_tx_data = match partial_deauthorize(tx_data) {
        Some(tx_data) => tx_data,
        None => {
            return Err(StorageError::SimpleMessage(
                "Failed to partially de-authorize",
            ));
        }
    };

    let txid_parts = unauth_tx_data.digest(TxIdDigester);
    // the commitment being signed is shared across all Sapling inputs; once
    // V4 transactions are deprecated this should just be the txid, but
    // for now we need to continue to compute it here.
    let sighash =
        signature_hash(&unauth_tx_data, &SignableInput::Shielded, &txid_parts);
    tracing::debug!("sighash computed");

    let PVKs {
        spend_vk,
        convert_vk,
        output_vk,
    } = load_pvks();

    #[cfg(not(feature = "testing"))]
    let mut ctx = BatchValidator::new();
    #[cfg(feature = "testing")]
    let mut ctx = testing::MockBatchValidator::default();

    // Charge gas before check bundle
    charge_masp_check_bundle_gas(sapling_bundle, &consume_verify_gas)?;

    if !ctx.check_bundle(sapling_bundle.to_owned(), sighash.as_ref().to_owned())
    {
        tracing::debug!("failed check bundle");
        return Err(StorageError::SimpleMessage("Invalid sapling bundle"));
    }
    tracing::debug!("passed check bundle");

    // Charge gas before final validation
    charge_masp_validate_gas(sapling_bundle, consume_verify_gas)?;
    if !ctx.validate(spend_vk, convert_vk, output_vk, OsRng) {
        return Err(StorageError::SimpleMessage(
            "Invalid proofs or signatures",
        ));
    }
    Ok(())
}

// Charge gas for the check_bundle operation which does not leverage concurrency
fn charge_masp_check_bundle_gas<F>(
    sapling_bundle: &SaplingBundle<SaplingAuthorized>,
    consume_verify_gas: F,
) -> Result<(), namada_state::StorageError>
where
    F: Fn(u64) -> std::result::Result<(), namada_state::StorageError>,
{
    consume_verify_gas(checked!(
        (sapling_bundle.shielded_spends.len() as u64)
            * namada_gas::MASP_SPEND_CHECK_GAS
    )?)?;

    consume_verify_gas(checked!(
        (sapling_bundle.shielded_converts.len() as u64)
            * namada_gas::MASP_CONVERT_CHECK_GAS
    )?)?;

    consume_verify_gas(checked!(
        (sapling_bundle.shielded_outputs.len() as u64)
            * namada_gas::MASP_OUTPUT_CHECK_GAS
    )?)
}

// Charge gas for the final validation, taking advtange of concurrency for
// proofs verification but not for signatures
fn charge_masp_validate_gas<F>(
    sapling_bundle: &SaplingBundle<SaplingAuthorized>,
    consume_verify_gas: F,
) -> Result<(), namada_state::StorageError>
where
    F: Fn(u64) -> std::result::Result<(), namada_state::StorageError>,
{
    // Signatures gas
    consume_verify_gas(checked!(
        // Add one for the binding signature
        ((sapling_bundle.shielded_spends.len() as u64) + 1)
            * namada_gas::MASP_VERIFY_SIG_GAS
    )?)?;

    // If at least one note is present charge the fixed costs. Then charge the
    // variable cost for every other note, amortized on the fixed expected
    // number of cores
    if let Some(remaining_notes) =
        sapling_bundle.shielded_spends.len().checked_sub(1)
    {
        consume_verify_gas(namada_gas::MASP_FIXED_SPEND_GAS)?;
        consume_verify_gas(checked!(
            namada_gas::MASP_VARIABLE_SPEND_GAS * remaining_notes as u64
                / namada_gas::MASP_PARALLEL_GAS_DIVIDER
        )?)?;
    }

    if let Some(remaining_notes) =
        sapling_bundle.shielded_converts.len().checked_sub(1)
    {
        consume_verify_gas(namada_gas::MASP_FIXED_CONVERT_GAS)?;
        consume_verify_gas(checked!(
            namada_gas::MASP_VARIABLE_CONVERT_GAS * remaining_notes as u64
                / namada_gas::MASP_PARALLEL_GAS_DIVIDER
        )?)?;
    }

    if let Some(remaining_notes) =
        sapling_bundle.shielded_outputs.len().checked_sub(1)
    {
        consume_verify_gas(namada_gas::MASP_FIXED_OUTPUT_GAS)?;
        consume_verify_gas(checked!(
            namada_gas::MASP_VARIABLE_OUTPUT_GAS * remaining_notes as u64
                / namada_gas::MASP_PARALLEL_GAS_DIVIDER
        )?)?;
    }

    Ok(())
}

/// Get the path to MASP parameters from [`ENV_VAR_MASP_PARAMS_DIR`] env var or
/// use the default.
pub fn get_params_dir() -> PathBuf {
    if let Ok(params_dir) = env::var(ENV_VAR_MASP_PARAMS_DIR) {
        #[allow(clippy::print_stdout)]
        {
            println!("Using {} as masp parameter folder.", params_dir);
        }
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

impl<P1, N1>
    MapBuilder<P1, ExtendedSpendingKey, N1, (), ExtendedFullViewingKey, ()>
    for WalletMap
{
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
#[derive(BorshSerialize, BorshDeserialize, BorshDeserializer, Debug, Clone)]
pub struct MaspChange {
    /// the token address
    pub asset: Address,
    /// the change in the token
    pub change: token::Change,
}

/// a masp amount
pub type MaspAmount = ValueSum<(Option<MaspEpoch>, Address), token::Change>;

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
/// An invariant that shielded-sync maintains is that
/// this cache either contains all transactions from
/// a given height, or none.
#[derive(Debug, Default, Clone)]
pub struct Unscanned {
    txs: Arc<Mutex<IndexedNoteData>>,
}

impl BorshSerialize for Unscanned {
    fn serialize<W: Write>(&self, writer: &mut W) -> std::io::Result<()> {
        let locked = self.txs.lock().unwrap();
        let bytes = locked.serialize_to_vec();
        writer.write(&bytes).map(|_| ())
    }
}

impl BorshDeserialize for Unscanned {
    fn deserialize_reader<R: Read>(reader: &mut R) -> std::io::Result<Self> {
        let unscanned = IndexedNoteData::deserialize_reader(reader)?;
        Ok(Self {
            txs: Arc::new(Mutex::new(unscanned)),
        })
    }
}

impl Unscanned {
    /// Append elements to the cache from an iterator.
    pub fn extend<I>(&self, items: I)
    where
        I: IntoIterator<Item = IndexedNoteEntry>,
    {
        let mut locked = self.txs.lock().unwrap();
        locked.extend(items);
    }

    /// Add a single entry to the cache.
    pub fn insert(&self, (k, v): IndexedNoteEntry) {
        let mut locked = self.txs.lock().unwrap();
        locked.insert(k, v);
    }

    /// Check if this cache has already been populated for a given
    /// block height.
    pub fn contains_height(&self, height: u64) -> bool {
        let locked = self.txs.lock().unwrap();
        locked.keys().any(|k| k.height.0 == height)
    }

    /// We remove all indices from blocks that have been entirely scanned.
    /// If a block is only partially scanned, we leave all the events in the
    /// cache.
    pub fn scanned(&self, ix: &IndexedTx) {
        let mut locked = self.txs.lock().unwrap();
        locked.retain(|i, _| i.height >= ix.height);
    }

    /// Gets the latest block height present in the cache
    pub fn latest_height(&self) -> BlockHeight {
        let txs = self.txs.lock().unwrap();
        txs.keys()
            .max_by_key(|ix| ix.height)
            .map(|ix| ix.height)
            .unwrap_or_default()
    }

    /// Gets the first block height present in the cache
    pub fn first_height(&self) -> BlockHeight {
        let txs = self.txs.lock().unwrap();
        txs.keys()
            .min_by_key(|ix| ix.height)
            .map(|ix| ix.height)
            .unwrap_or_default()
    }

    /// Remove the first entry from the cache and return it.
    pub fn pop_first(&self) -> Option<IndexedNoteEntry> {
        let mut locked = self.txs.lock().unwrap();
        locked.pop_first()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        let locked = self.txs.lock().unwrap();
        locked.is_empty()
    }
}

impl IntoIterator for Unscanned {
    type IntoIter = <IndexedNoteData as IntoIterator>::IntoIter;
    type Item = IndexedNoteEntry;

    fn into_iter(self) -> Self::IntoIter {
        let txs = {
            let mut locked = self.txs.lock().unwrap();
            std::mem::take(&mut *locked)
        };
        txs.into_iter()
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
    /// scan new MASP transactions.
    fn update_witness_map(
        &mut self,
        indexed_tx: IndexedTx,
        shielded: &[Transaction],
    ) -> Result<(), Error> {
        let mut note_pos = self.tree.size();
        self.tx_note_map.insert(indexed_tx, note_pos);

        for tx in shielded {
            for so in
                tx.sapling_bundle().map_or(&vec![], |x| &x.shielded_outputs)
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
        }
        Ok(())
    }

    /// Fetch the current state of the multi-asset shielded pool into a
    /// ShieldedContext
    #[allow(clippy::too_many_arguments)]
    #[cfg(not(target_family = "wasm"))]
    pub async fn fetch<'client, C, IO, M>(
        &mut self,
        client: M,
        progress: &impl ProgressTracker<IO>,
        start_query_height: Option<BlockHeight>,
        last_query_height: Option<BlockHeight>,
        retry: RetryStrategy,
        // NOTE: do not remove this argument, it will be used once the indexer
        // is ready
        _batch_size: u64,
        sks: &[ExtendedSpendingKey],
        fvks: &[ViewingKey],
    ) -> Result<(), Error>
    where
        C: Client + Sync,
        IO: Io,
        M: MaspClient<'client, C> + 'client,
    {
        let shutdown_signal = control_flow::install_shutdown_signal();
        self.fetch_aux(
            client,
            progress,
            start_query_height,
            last_query_height,
            retry,
            _batch_size,
            sks,
            fvks,
            shutdown_signal,
        )
        .await
    }

    fn min_height_to_sync_from(&self) -> Result<BlockHeight, Error> {
        let Some(maybe_least_synced_vk_height) =
            self.vk_heights.values().min().cloned()
        else {
            return Err(Error::Other(
                "No viewing keys are available in the shielded context to \
                 decrypt notes with"
                    .to_string(),
            ));
        };
        let maybe_last_witnessed_tx = self.tx_note_map.keys().max().cloned();
        let last_height_in_witnesses = std::cmp::min(
            maybe_last_witnessed_tx.as_ref(),
            maybe_least_synced_vk_height.as_ref(),
        )
        .map(|ix| ix.height);
        Ok(last_height_in_witnesses.unwrap_or_else(BlockHeight::first))
    }

    #[allow(clippy::too_many_arguments)]
    #[cfg(not(target_family = "wasm"))]
    async fn fetch_aux<'client, C, IO, M>(
        &mut self,
        client: M,
        progress: &impl ProgressTracker<IO>,
        start_query_height: Option<BlockHeight>,
        last_query_height: Option<BlockHeight>,
        retry: RetryStrategy,
        // NOTE: do not remove this argument, it will be used once the indexer
        // is ready
        _batch_size: u64,
        sks: &[ExtendedSpendingKey],
        fvks: &[ViewingKey],
        mut shutdown_signal: ShutdownSignal,
    ) -> Result<(), Error>
    where
        C: Client + Sync,
        IO: Io,
        M: MaspClient<'client, C> + 'client,
    {
        if start_query_height > last_query_height {
            return Err(Error::Other(format!(
                "The start height {start_query_height:?} cannot be higher \
                 than the ending height {last_query_height:?} in the shielded \
                 sync"
            )));
        }

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

        // Save the context to persist newly added keys
        let _ = self.save().await;

        // the latest block height which has been added to the witness Merkle
        // tree
        let last_witnessed_tx = self.tx_note_map.keys().max().cloned();

        // Query for the last produced block height
        let Some(last_block_height) =
            query_block(client.rpc_client()).await?.map(|b| b.height)
        else {
            return Err(Error::Other(
                "No block has been committed yet".to_string(),
            ));
        };

        let last_query_height = last_query_height
            .unwrap_or(last_block_height)
            // NB: limit fetching until the last committed height
            .min(last_block_height);

        let mut start_height = start_query_height
            .map_or_else(|| self.min_height_to_sync_from(), Ok)?
            // NB: the start height cannot be greater than
            // `last_query_height`
            .min(last_query_height);

        for _ in retry {
            debug_assert!(start_height <= last_query_height);

            // a stateful channel that communicates notes fetched to the trial
            // decryption process
            let (fetch_send, fetch_recv) =
                fetch_channel::new(self.unscanned.clone());
            let fetch_res = self
                .fetch_shielded_transfers(
                    &client,
                    progress,
                    &mut shutdown_signal,
                    fetch_send,
                    start_height,
                    last_query_height,
                )
                .await;
            // if fetching errored, log it. But this is recoverable.
            match fetch_res {
                Err(e @ Error::Interrupt(_)) => {
                    display_line!(progress.io(), "{}", e.to_string(),);
                    return Err(e);
                }
                Err(e) => display_line!(
                    progress.io(),
                    "Error encountered while fetching: {}",
                    e.to_string(),
                ),
                _ => {}
            }
            let txs = progress.scan(fetch_recv);
            for (ref indexed_tx, ref stx) in txs {
                if Some(indexed_tx) > last_witnessed_tx.as_ref() {
                    self.update_witness_map(indexed_tx.to_owned(), stx)?;
                }
                let mut vk_heights = BTreeMap::new();
                std::mem::swap(&mut vk_heights, &mut self.vk_heights);
                for (vk, h) in vk_heights
                    .iter_mut()
                    .filter(|(_vk, h)| h.as_ref() < Some(indexed_tx))
                {
                    self.scan_tx(indexed_tx.to_owned(), stx, vk)?;
                    *h = Some(indexed_tx.to_owned());
                }
                // possibly remove unneeded elements from the cache.
                self.unscanned.scanned(indexed_tx);
                std::mem::swap(&mut vk_heights, &mut self.vk_heights);
                if shutdown_signal.received() {
                    let _ = self.save().await;
                    return Err(Error::Interrupt(
                        "[ShieldedSync::Scanning]".to_string(),
                    ));
                }
            }

            // If fetching failed before completing, we restart
            // the process from the height we managed to sync to.
            // Otherwise, we can break the loop.
            if progress.left_to_fetch() == 0 {
                break;
            }

            start_height = self.min_height_to_sync_from()?.clamp(
                start_query_height.unwrap_or_else(BlockHeight::first),
                last_query_height,
            );
        }
        _ = self.save().await;

        if progress.left_to_fetch() != 0 {
            Err(Error::Other(
                "After retrying, could not fetch all MASP txs.".to_string(),
            ))
        } else {
            Ok(())
        }
    }

    /// Obtain a chronologically-ordered list of all accepted shielded
    /// transactions from a node.
    async fn fetch_shielded_transfers<
        'client,
        C: Client + Sync,
        IO: Io,
        M: MaspClient<'client, C> + 'client,
    >(
        &self,
        client: &M,
        progress: &impl ProgressTracker<IO>,
        shutdown_signal: &mut ShutdownSignal,
        block_sender: FetchQueueSender,
        last_indexed_tx: BlockHeight,
        last_query_height: BlockHeight,
    ) -> Result<(), Error> {
        // Fetch all the transactions we do not have yet
        let first_height_to_query = last_indexed_tx;
        let res = client
            .fetch_shielded_transfers(
                progress,
                shutdown_signal,
                block_sender,
                first_height_to_query,
                last_query_height,
            )
            .await;
        // persist fetched notes
        _ = self.save().await;
        res
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
        shielded: &[Transaction],
        vk: &ViewingKey,
    ) -> Result<(), Error> {
        type Proof = OutputDescription<
            <
                <Authorized as Authorization>::SaplingAuth
                as masp_primitives::transaction::components::sapling::Authorization
            >::Proof
        >;

        // For tracking the account changes caused by this Transaction
        let mut transaction_delta = TransactionDelta::new();
        if let ContextSyncStatus::Confirmed = self.sync_status {
            let mut note_pos = self.tx_note_map[&indexed_tx];
            // Listen for notes sent to our viewing keys, only if we are syncing
            // (i.e. in a confirmed status)
            for tx in shielded {
                for so in
                    tx.sapling_bundle().map_or(&vec![], |x| &x.shielded_outputs)
                {
                    // Let's try to see if this viewing key can decrypt latest
                    // note
                    let notes = self.pos_map.entry(*vk).or_default();
                    let decres = try_sapling_note_decryption::<_, Proof>(
                        &NETWORK,
                        1.into(),
                        &PreparedIncomingViewingKey::new(&vk.ivk()),
                        so,
                    );
                    // So this current viewing key does decrypt this current
                    // note...
                    if let Some((note, pa, memo)) = decres {
                        // Add this note to list of notes decrypted by this
                        // viewing key
                        notes.insert(note_pos);
                        // Compute the nullifier now to quickly recognize when
                        // spent
                        let nf = note.nf(
                            &vk.nk,
                            note_pos.try_into().map_err(|_| {
                                Error::Other(
                                    "Can not get nullifier".to_string(),
                                )
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
        }

        // Cancel out those of our notes that have been spent
        for tx in shielded {
            for ss in
                tx.sapling_bundle().map_or(&vec![], |x| &x.shielded_spends)
            {
                // If the shielded spend's nullifier is in our map, then target
                // note is rendered unusable
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
        }

        Ok(())
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
        target_epoch: MaspEpoch,
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
        let trace = I128Sum::from_pair(asset_type, value % threshold);
        let normed_trace =
            I128Sum::from_pair(normed_asset_type, value % threshold);
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
        target_epoch: MaspEpoch,
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
        target_epoch: MaspEpoch,
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
                    I128Sum::from_pair(note.asset_type, note.value as i128);
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

    /// Convert an amount whose units are AssetTypes to one whose units are
    /// Addresses that they decode to. All asset types not corresponding to
    /// the given epoch are ignored.
    pub async fn decode_combine_sum_to_epoch<C: Client + Sync>(
        &mut self,
        client: &C,
        amt: I128Sum,
        target_epoch: MaspEpoch,
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
                    );
                }
                None => {
                    undecoded += ValueSum::from_pair(*asset_type, *val);
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
                );
            } else {
                undecoded += ValueSum::from_pair(*asset_type, *val);
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
                res += ValueSum::from_pair((*asset_type, decoded), *val);
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
        let epoch = rpc::query_masp_epoch(context.client()).await?;
        // Context required for storing which notes are in the source's
        // possession
        let memo = MemoBytes::empty();

        // Try to get a seed from env var, if any.
        #[allow(unused_mut)]
        let mut rng = StdRng::from_rng(OsRng).unwrap();
        #[cfg(feature = "testing")]
        let mut rng = if let Ok(seed) = env::var(ENV_VAR_MASP_TEST_SEED)
            .map_err(|e| Error::Other(e.to_string()))
            .and_then(|seed| {
                let exp_str =
                    format!("Env var {ENV_VAR_MASP_TEST_SEED} must be a u64.");
                let parsed_seed: u64 =
                    seed.parse().map_err(|_| Error::Other(exp_str))?;
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
        // TODO: if the user requested the default expiration, there might be a
        // small discrepancy between the datetime we calculate here and the one
        // we set for the transaction. This should be small enough to not cause
        // any issue, in case refactor this function to request the precise
        // datetime to the caller
        let expiration_height: u32 = match context
            .tx_builder()
            .expiration
            .to_datetime()
        {
            Some(expiration) => {
                // Try to match a DateTime expiration with a plausible
                // corresponding block height
                let last_block_height: u64 =
                    crate::rpc::query_block(context.client())
                        .await?
                        .map_or_else(|| 1, |block| u64::from(block.height));
                #[allow(clippy::disallowed_methods)]
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
        let mut builder = Builder::<Network, _>::new(
            NETWORK,
            // NOTE: this is going to add 20 more blocks to the actual
            // expiration but there's no other exposed function that we could
            // use from the masp crate to specify the expiration better
            expiration_height.into(),
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
        let value_balance = builder.value_balance();
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
                shortfall += I128Sum::from_pair(*asset_type, val.into());
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
            for (asset_type, amt) in builder.value_balance().components() {
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
        let (masp_tx, metadata) = builder.build(
            &prover,
            &FeeRule::non_standard(U64Sum::zero()),
            &mut rng,
            &mut RngBuildParams::new(OsRng),
        )?;

        if update_ctx {
            // Cache the generated transfer
            let mut shielded_ctx = context.shielded_mut().await;
            shielded_ctx
                .pre_cache_transaction(context, &[masp_tx.clone()])
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
    // transaction. More specifically invalidate the spent notes, but do not
    // cache the newly produced output descriptions and therefore the merkle
    // tree
    async fn pre_cache_transaction(
        &mut self,
        context: &impl Namada,
        masp_tx: &[Transaction],
    ) -> Result<(), Error> {
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
        let indexed_tx =
            last_witnessed_tx.map_or_else(IndexedTx::default, |indexed| {
                IndexedTx {
                    height: indexed.height,
                    index: indexed
                        .index
                        .checked_add(1)
                        .expect("Tx index shouldn't overflow"),
                }
            });
        self.sync_status = ContextSyncStatus::Speculative;
        for vk in vks {
            self.vk_heights.entry(vk).or_default();

            self.scan_tx(indexed_tx.clone(), masp_tx, &vk)?;
        }
        // Save the speculative state for future usage
        self.save().await.map_err(|e| Error::Other(e.to_string()))?;

        Ok(())
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
        epoch: MaspEpoch,
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

/// Extract the relevant shield portions of a [`Tx`], if any.
async fn extract_masp_tx(
    tx: &Tx,
    masp_section_refs: &MaspTxRefs,
) -> Result<Vec<Transaction>, Error> {
    // NOTE: simply looking for masp sections attached to the tx
    // is not safe. We don't validate the sections attached to a
    // transaction se we could end up with transactions carrying
    // an unnecessary masp section. We must instead look for the
    // required masp sections coming from the events

    masp_section_refs
        .0
        .iter()
        .try_fold(vec![], |mut acc, hash| {
            match tx
                .get_section(hash)
                .and_then(|section| section.masp_tx())
                .ok_or_else(|| {
                    Error::Other(
                        "Missing expected masp transaction".to_string(),
                    )
                }) {
                Ok(transaction) => {
                    acc.push(transaction);
                    Ok(acc)
                }
                Err(e) => Err(e),
            }
        })
}

// Retrieves all the indexes at the specified height which refer
// to a valid masp transaction. If an index is given, it filters only the
// transactions with an index equal or greater to the provided one.
async fn get_indexed_masp_events_at_height<C: Client + Sync>(
    client: &C,
    height: BlockHeight,
    first_idx_to_query: Option<TxIndex>,
) -> Result<Option<Vec<(TxIndex, MaspTxRefs)>>, Error> {
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
                        MaspTxBlockIndexAttr::read_from_event_attributes(
                            &event.attributes,
                        )
                        .ok()?;

                    if tx_index >= first_idx_to_query {
                        // Extract the references to the correct masp sections
                        let masp_section_refs =
                            MaspTxBatchRefsAttr::read_from_event_attributes(
                                &event.attributes,
                            )
                            .ok()?;

                        Some((tx_index, masp_section_refs))
                    } else {
                        None
                    }
                })
                .collect::<Vec<_>>()
        }))
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
    use masp_primitives::group::GroupEncoding;
    use masp_primitives::sapling::prover::TxProver;
    use masp_primitives::sapling::redjubjub::{PublicKey, Signature};
    use masp_primitives::sapling::{ProofGenerationKey, Rseed};
    use masp_primitives::transaction::components::sapling::builder::StoredBuildParams;
    use masp_primitives::transaction::components::sapling::Bundle;
    use masp_primitives::transaction::components::GROTH_PROOF_SIZE;
    use masp_proofs::bellman::groth16::{self, Proof};
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
    use crate::token::testing::arb_denomination;

    /// A context object for verifying the Sapling components of MASP
    /// transactions. Same as BatchValidator, but always assumes the
    /// proofs and signatures to be valid.
    pub struct MockBatchValidator {
        inner: BatchValidator,
    }

    impl Default for MockBatchValidator {
        fn default() -> Self {
            MockBatchValidator {
                inner: BatchValidator::new(),
            }
        }
    }

    impl MockBatchValidator {
        /// Checks the bundle against Sapling-specific consensus rules, and adds
        /// its proof and signatures to the validator.
        ///
        /// Returns `false` if the bundle doesn't satisfy all of the consensus
        /// rules. This `BatchValidator` can continue to be used
        /// regardless, but some or all of the proofs and signatures
        /// from this bundle may have already been added to the batch even if
        /// it fails other consensus rules.
        pub fn check_bundle(
            &mut self,
            bundle: Bundle<
                masp_primitives::transaction::components::sapling::Authorized,
            >,
            sighash: [u8; 32],
        ) -> bool {
            self.inner.check_bundle(bundle, sighash)
        }

        /// Batch-validates the accumulated bundles.
        ///
        /// Returns `true` if every proof and signature in every bundle added to
        /// the batch validator is valid, or `false` if one or more are
        /// invalid. No attempt is made to figure out which of the
        /// accumulated bundles might be invalid; if that information is
        /// desired, construct separate [`BatchValidator`]s for sub-batches of
        /// the bundles.
        pub fn validate<R: RngCore + CryptoRng>(
            self,
            _spend_vk: &groth16::VerifyingKey<Bls12>,
            _convert_vk: &groth16::VerifyingKey<Bls12>,
            _output_vk: &groth16::VerifyingKey<Bls12>,
            mut _rng: R,
        ) -> bool {
            true
        }
    }

    /// This function computes `value` in the exponent of the value commitment
    /// base
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

    /// A context object for creating the Sapling components of a Zcash
    /// transaction.
    pub struct SaplingProvingContext {
        bsk: jubjub::Fr,
        // (sum of the Spend value commitments) - (sum of the Output value
        // commitments)
        cv_sum: jubjub::ExtendedPoint,
    }

    /// An implementation of TxProver that does everything except generating
    /// valid zero-knowledge proofs. Uses the supplied source of randomness to
    /// carry out its operations.
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
            rcv: jubjub::Fr,
        ) -> Result<
            ([u8; GROTH_PROOF_SIZE], jubjub::ExtendedPoint, PublicKey),
            (),
        > {
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
            rcv: jubjub::Fr,
        ) -> ([u8; GROTH_PROOF_SIZE], jubjub::ExtendedPoint) {
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
            rcv: jubjub::Fr,
        ) -> Result<([u8; GROTH_PROOF_SIZE], jubjub::ExtendedPoint), ()>
        {
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
    /// Adapts a CSPRNG from a PRNG for proptesting
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
        /// Expose a random number generator
        pub fn arb_rng()(rng in Just(()).prop_perturb(|(), rng| rng)) -> TestRng {
            rng
        }
    }

    prop_compose! {
        /// Generate an arbitrary output description with the given value
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
        /// Generate an arbitrary spend description with the given value
        pub fn arb_spend_description(
            asset_type: AssetType,
            value: u64,
        )(
            address in arb_transparent_address(),
            expiration_height in arb_height(BranchId::MASP, &Network),
            mut rng in arb_rng().prop_map(TestCsprng),
            bparams_rng in arb_rng().prop_map(TestCsprng),
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

            let mut builder = Builder::<Network, _>::new(
                NETWORK,
                // NOTE: this is going to add 20 more blocks to the actual
                // expiration but there's no other exposed function that we could
                // use from the masp crate to specify the expiration better
                expiration_height.unwrap(),
            );
            // Add a transparent input to support our desired shielded output
            builder.add_transparent_input(TxOut { asset_type, value, address }).unwrap();
            // Finally add the shielded output that we need
            builder.add_sapling_output(None, payment_addr, asset_type, value, MemoBytes::empty()).unwrap();
            // Build a transaction in order to get its shielded outputs
            let (transaction, metadata) = builder.build(
                &MockTxProver(Mutex::new(prover_rng)),
                &FeeRule::non_standard(U64Sum::zero()),
                &mut rng,
                &mut RngBuildParams::new(bparams_rng),
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
        /// Generate an arbitrary MASP denomination
        pub fn arb_masp_digit_pos()(denom in 0..4u8) -> MaspDigitPos {
            MaspDigitPos::from(denom)
        }
    }

    // Maximum value for a note partition
    const MAX_MONEY: u64 = 100;
    // Maximum number of partitions for a note
    const MAX_SPLITS: usize = 3;

    prop_compose! {
        /// Arbitrarily partition the given vector of integers into sets and sum
        /// them
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
        /// Generate arbitrary spend descriptions with the given asset type
        /// partitioning the given values
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
        /// Generate arbitrary output descriptions with the given asset type
        /// partitioning the given values
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
        /// Generate arbitrary spend descriptions with the given asset type
        /// partitioning the given values
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
        /// Generate an arbitrary shielded MASP transaction builder
        pub fn arb_shielded_builder(asset_range: impl Into<SizeRange>)(
            assets in collection::hash_map(
                arb_pre_asset_type(),
                collection::vec(..MAX_MONEY, ..MAX_SPLITS),
                asset_range,
            ),
        )(
            expiration_height in arb_height(BranchId::MASP, &Network),
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
            Builder::<Network>,
            HashMap<AssetData, u64>,
        ) {
            let mut builder = Builder::<Network, _>::new(
                NETWORK,
                // NOTE: this is going to add 20 more blocks to the actual
                // expiration but there's no other exposed function that we could
                // use from the masp crate to specify the expiration better
                expiration_height.unwrap(),
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
        /// Generate an arbitrary masp epoch
        pub fn arb_masp_epoch()(epoch: u64) -> MaspEpoch{
            MaspEpoch::new(epoch)
        }
    }

    prop_compose! {
        /// Generate an arbitrary pre-asset type
        pub fn arb_pre_asset_type()(
            token in arb_address(),
            denom in arb_denomination(),
            position in arb_masp_digit_pos(),
            epoch in option::of(arb_masp_epoch()),
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
        /// Generate an arbitrary shielding MASP transaction builder
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
            expiration_height in arb_height(BranchId::MASP, &Network),
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
            Builder::<Network>,
            HashMap<AssetData, u64>,
        ) {
            let mut builder = Builder::<Network, _>::new(
                NETWORK,
                // NOTE: this is going to add 20 more blocks to the actual
                // expiration but there's no other exposed function that we could
                // use from the masp crate to specify the expiration better
                expiration_height.unwrap(),
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
        /// Generate an arbitrary deshielding MASP transaction builder
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
            expiration_height in arb_height(BranchId::MASP, &Network),
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
            Builder::<Network>,
            HashMap<AssetData, u64>,
        ) {
            let mut builder = Builder::<Network, _>::new(
                NETWORK,
                // NOTE: this is going to add 20 more blocks to the actual
                // expiration but there's no other exposed function that we could
                // use from the masp crate to specify the expiration better
                expiration_height.unwrap(),
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
        /// Generate an arbitrary MASP shielded transfer
        pub fn arb_shielded_transfer(
            asset_range: impl Into<SizeRange>,
        )(asset_range in Just(asset_range.into()))(
            (builder, asset_types) in arb_shielded_builder(asset_range),
            epoch in arb_masp_epoch(),
            prover_rng in arb_rng().prop_map(TestCsprng),
            mut rng in arb_rng().prop_map(TestCsprng),
            bparams_rng in arb_rng().prop_map(TestCsprng),
        ) -> (ShieldedTransfer, HashMap<AssetData, u64>, StoredBuildParams) {
            let mut rng_build_params = RngBuildParams::new(bparams_rng);
            let (masp_tx, metadata) = builder.clone().build(
                &MockTxProver(Mutex::new(prover_rng)),
                &FeeRule::non_standard(U64Sum::zero()),
                &mut rng,
                &mut rng_build_params,
            ).unwrap();
            (ShieldedTransfer {
                builder: builder.map_builder(WalletMap),
                metadata,
                masp_tx,
                epoch,
            }, asset_types, rng_build_params.to_stored().unwrap())
        }
    }

    prop_compose! {
        /// Generate an arbitrary MASP shielded transfer
        pub fn arb_shielding_transfer(
            source: TransparentAddress,
            asset_range: impl Into<SizeRange>,
        )(asset_range in Just(asset_range.into()))(
            (builder, asset_types) in arb_shielding_builder(
                source,
                asset_range,
            ),
            epoch in arb_masp_epoch(),
            prover_rng in arb_rng().prop_map(TestCsprng),
            mut rng in arb_rng().prop_map(TestCsprng),
            bparams_rng in arb_rng().prop_map(TestCsprng),
        ) -> (ShieldedTransfer, HashMap<AssetData, u64>, StoredBuildParams) {
            let mut rng_build_params = RngBuildParams::new(bparams_rng);
            let (masp_tx, metadata) = builder.clone().build(
                &MockTxProver(Mutex::new(prover_rng)),
                &FeeRule::non_standard(U64Sum::zero()),
                &mut rng,
                &mut rng_build_params,
            ).unwrap();
            (ShieldedTransfer {
                builder: builder.map_builder(WalletMap),
                metadata,
                masp_tx,
                epoch,
            }, asset_types, rng_build_params.to_stored().unwrap())
        }
    }

    prop_compose! {
        /// Generate an arbitrary MASP shielded transfer
        pub fn arb_deshielding_transfer(
            target: TransparentAddress,
            asset_range: impl Into<SizeRange>,
        )(asset_range in Just(asset_range.into()))(
            (builder, asset_types) in arb_deshielding_builder(
                target,
                asset_range,
            ),
            epoch in arb_masp_epoch(),
            prover_rng in arb_rng().prop_map(TestCsprng),
            mut rng in arb_rng().prop_map(TestCsprng),
            bparams_rng in arb_rng().prop_map(TestCsprng),
        ) -> (ShieldedTransfer, HashMap<AssetData, u64>, StoredBuildParams) {
            let mut rng_build_params = RngBuildParams::new(bparams_rng);
            let (masp_tx, metadata) = builder.clone().build(
                &MockTxProver(Mutex::new(prover_rng)),
                &FeeRule::non_standard(U64Sum::zero()),
                &mut rng,
                &mut rng_build_params,
            ).unwrap();
            (ShieldedTransfer {
                builder: builder.map_builder(WalletMap),
                metadata,
                masp_tx,
                epoch,
            }, asset_types, rng_build_params.to_stored().unwrap())
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
                #[allow(clippy::print_stdout)]
                {
                    println!("MASP parameters not present, downloading...");
                }
                masp_proofs::download_masp_parameters(None)
                    .expect("MASP parameters not present or downloadable");
                #[allow(clippy::print_stdout)]
                {
                    println!(
                        "MASP parameter download complete, resuming \
                         execution..."
                    );
                }
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

#[cfg(test)]
mod test_shielded_sync {
    use core::str::FromStr;
    use std::collections::BTreeSet;

    use borsh::BorshDeserialize;
    use masp_primitives::transaction::Transaction;
    use masp_primitives::zip32::ExtendedFullViewingKey;
    use namada_core::masp::ExtendedViewingKey;
    use namada_core::storage::{BlockHeight, TxIndex};
    use namada_tx::IndexedTx;
    use tempfile::tempdir;

    use crate::control_flow::testing_shutdown_signal;
    use crate::error::Error;
    use crate::io::StdIo;
    use crate::masp::fs::FsShieldedUtils;
    use crate::masp::test_utils::{
        test_client, TestUnscannedTracker, TestingMaspClient,
    };
    use crate::masp::utils::{DefaultTracker, ProgressTracker, RetryStrategy};

    // A viewing key derived from A_SPENDING_KEY
    pub const AA_VIEWING_KEY: &str = "zvknam1qqqqqqqqqqqqqq9v0sls5r5de7njx8ehu49pqgmqr9ygelg87l5x8y4s9r0pjlvu6x74w9gjpw856zcu826qesdre628y6tjc26uhgj6d9zqur9l5u3p99d9ggc74ald6s8y3sdtka74qmheyqvdrasqpwyv2fsmxlz57lj4grm2pthzj3sflxc0jx0edrakx3vdcngrfjmru8ywkguru8mxss2uuqxdlglaz6undx5h8w7g70t2es850g48xzdkqay5qs0yw06rtxcpjdve6";

    /// A serialized transaction that will work for testing.
    /// Would love to do this in a less opaque fashion, but
    /// making these things is a misery not worth my time.
    ///
    /// This a tx sending 1 BTC from Albert to Albert's PA
    fn arbitrary_masp_tx() -> Transaction {
        Transaction::try_from_slice(&[
            2, 0, 0, 0, 10, 39, 167, 38, 166, 117, 255, 233, 0, 0, 0, 0, 255,
            255, 255, 255, 1, 162, 120, 217, 193, 173, 117, 92, 126, 107, 199,
            182, 72, 95, 60, 122, 52, 9, 134, 72, 4, 167, 41, 187, 171, 17,
            124, 114, 84, 191, 75, 37, 2, 0, 225, 245, 5, 0, 0, 0, 0, 93, 213,
            181, 21, 38, 32, 230, 52, 155, 4, 203, 26, 70, 63, 59, 179, 142, 7,
            72, 76, 0, 0, 0, 1, 132, 100, 41, 23, 128, 97, 116, 40, 195, 40,
            46, 55, 79, 106, 234, 32, 4, 216, 106, 88, 173, 65, 140, 99, 239,
            71, 103, 201, 111, 149, 166, 13, 73, 224, 253, 98, 27, 199, 11,
            142, 56, 214, 4, 96, 35, 72, 83, 86, 194, 107, 163, 194, 238, 37,
            19, 171, 8, 129, 53, 246, 64, 220, 155, 47, 177, 165, 109, 232, 84,
            247, 128, 184, 40, 26, 113, 196, 190, 181, 57, 213, 45, 144, 46,
            12, 145, 128, 169, 116, 65, 51, 208, 239, 50, 217, 224, 98, 179,
            53, 18, 130, 183, 114, 225, 21, 34, 175, 144, 125, 239, 240, 82,
            100, 174, 1, 192, 32, 187, 208, 205, 31, 108, 59, 87, 201, 148,
            214, 244, 255, 8, 150, 100, 225, 11, 245, 221, 170, 85, 241, 110,
            50, 90, 151, 210, 169, 41, 3, 23, 160, 196, 117, 211, 217, 121, 9,
            42, 236, 19, 149, 94, 62, 163, 222, 172, 128, 197, 56, 100, 233,
            227, 239, 60, 182, 191, 55, 148, 17, 0, 168, 198, 84, 87, 191, 89,
            229, 9, 129, 165, 98, 200, 127, 225, 192, 58, 0, 92, 104, 97, 26,
            125, 169, 209, 40, 170, 29, 93, 16, 114, 174, 23, 233, 218, 112,
            26, 175, 196, 198, 197, 159, 167, 157, 16, 232, 247, 193, 44, 82,
            143, 238, 179, 77, 87, 153, 3, 33, 207, 215, 142, 104, 179, 17,
            252, 148, 215, 150, 76, 56, 169, 13, 240, 4, 195, 221, 45, 250, 24,
            51, 243, 174, 176, 47, 117, 38, 1, 124, 193, 191, 55, 11, 164, 97,
            83, 188, 92, 202, 229, 106, 236, 165, 85, 236, 95, 255, 28, 71, 18,
            173, 202, 47, 63, 226, 129, 203, 154, 54, 155, 177, 161, 106, 210,
            220, 193, 142, 44, 105, 46, 164, 83, 136, 63, 24, 172, 157, 117, 9,
            202, 99, 223, 144, 36, 26, 154, 84, 175, 119, 12, 102, 71, 33, 14,
            131, 250, 86, 215, 153, 18, 94, 213, 61, 196, 67, 132, 204, 89,
            235, 241, 188, 147, 236, 92, 46, 83, 169, 236, 12, 34, 33, 65, 243,
            18, 23, 29, 41, 252, 207, 17, 196, 55, 56, 141, 158, 116, 227, 195,
            159, 233, 72, 26, 69, 72, 213, 50, 101, 161, 127, 213, 35, 210,
            223, 201, 219, 198, 192, 125, 129, 222, 178, 241, 116, 59, 255, 72,
            163, 46, 21, 222, 74, 202, 117, 217, 22, 188, 203, 2, 150, 38, 78,
            78, 250, 45, 36, 225, 240, 227, 115, 33, 114, 189, 25, 9, 219, 239,
            57, 103, 19, 109, 11, 5, 156, 43, 35, 53, 219, 250, 215, 185, 173,
            11, 101, 221, 29, 130, 74, 110, 225, 183, 77, 13, 52, 90, 183, 93,
            212, 175, 132, 21, 229, 109, 188, 124, 103, 3, 39, 174, 140, 115,
            67, 49, 100, 231, 129, 32, 24, 201, 196, 247, 33, 155, 20, 139, 34,
            3, 183, 12, 164, 6, 10, 219, 207, 151, 160, 4, 201, 160, 12, 156,
            82, 142, 226, 19, 134, 144, 53, 220, 140, 61, 74, 151, 129, 102,
            214, 73, 107, 147, 4, 98, 68, 79, 225, 103, 242, 187, 170, 102,
            225, 114, 4, 87, 96, 7, 212, 150, 127, 211, 158, 54, 86, 15, 191,
            21, 116, 202, 195, 60, 65, 134, 22, 2, 44, 133, 64, 181, 121, 66,
            218, 227, 72, 148, 63, 108, 227, 33, 66, 239, 77, 127, 139, 31, 16,
            150, 119, 198, 119, 229, 88, 188, 113, 80, 222, 86, 122, 181, 142,
            186, 130, 125, 236, 166, 95, 134, 243, 128, 65, 169, 33, 65, 73,
            182, 183, 156, 248, 39, 46, 199, 181, 85, 96, 126, 155, 189, 10,
            211, 145, 230, 94, 69, 232, 74, 87, 211, 46, 216, 30, 24, 38, 104,
            192, 165, 28, 73, 36, 227, 194, 41, 168, 5, 181, 176, 112, 67, 92,
            158, 212, 129, 207, 182, 223, 59, 185, 84, 210, 147, 32, 29, 61,
            56, 185, 21, 156, 114, 34, 115, 29, 25, 89, 152, 56, 55, 238, 43,
            0, 114, 89, 79, 95, 104, 143, 180, 51, 53, 108, 223, 236, 59, 47,
            188, 174, 196, 101, 180, 207, 162, 198, 104, 52, 67, 132, 178, 9,
            40, 10, 88, 206, 25, 132, 60, 136, 13, 213, 223, 81, 196, 131, 118,
            15, 53, 125, 165, 177, 170, 170, 17, 94, 53, 151, 51, 16, 170, 23,
            118, 255, 26, 46, 47, 37, 73, 165, 26, 43, 10, 221, 4, 132, 15, 78,
            214, 161, 3, 220, 10, 87, 139, 85, 61, 39, 131, 242, 216, 235, 52,
            93, 46, 180, 196, 151, 54, 207, 80, 223, 90, 252, 77, 10, 122, 175,
            229, 7, 144, 41, 1, 162, 120, 217, 193, 173, 117, 92, 126, 107,
            199, 182, 72, 95, 60, 122, 52, 9, 134, 72, 4, 167, 41, 187, 171,
            17, 124, 114, 84, 191, 75, 37, 2, 0, 31, 10, 250, 255, 255, 255,
            255, 255, 255, 255, 255, 255, 255, 255, 255, 151, 241, 211, 167,
            49, 151, 215, 148, 38, 149, 99, 140, 79, 169, 172, 15, 195, 104,
            140, 79, 151, 116, 185, 5, 161, 78, 58, 63, 23, 27, 172, 88, 108,
            85, 232, 63, 249, 122, 26, 239, 251, 58, 240, 10, 219, 34, 198,
            187, 147, 224, 43, 96, 82, 113, 159, 96, 125, 172, 211, 160, 136,
            39, 79, 101, 89, 107, 208, 208, 153, 32, 182, 26, 181, 218, 97,
            187, 220, 127, 80, 73, 51, 76, 241, 18, 19, 148, 93, 87, 229, 172,
            125, 5, 93, 4, 43, 126, 2, 74, 162, 178, 240, 143, 10, 145, 38, 8,
            5, 39, 45, 197, 16, 81, 198, 228, 122, 212, 250, 64, 59, 2, 180,
            81, 11, 100, 122, 227, 209, 119, 11, 172, 3, 38, 168, 5, 187, 239,
            212, 128, 86, 200, 193, 33, 189, 184, 151, 241, 211, 167, 49, 151,
            215, 148, 38, 149, 99, 140, 79, 169, 172, 15, 195, 104, 140, 79,
            151, 116, 185, 5, 161, 78, 58, 63, 23, 27, 172, 88, 108, 85, 232,
            63, 249, 122, 26, 239, 251, 58, 240, 10, 219, 34, 198, 187, 37,
            197, 248, 90, 113, 62, 149, 117, 145, 118, 42, 241, 60, 208, 83,
            57, 96, 143, 17, 128, 92, 118, 158, 188, 77, 37, 184, 164, 135,
            246, 196, 57, 198, 106, 139, 33, 15, 207, 0, 101, 143, 92, 178,
            132, 19, 106, 221, 246, 176, 100, 20, 114, 26, 55, 163, 14, 173,
            255, 121, 181, 58, 121, 140, 3,
        ])
        .expect("Test failed")
    }

    /// Test that if fetching fails before finishing,
    /// we re-establish the fetching process
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_retry_fetch() {
        let temp_dir = tempdir().unwrap();
        let mut shielded_ctx =
            FsShieldedUtils::new(temp_dir.path().to_path_buf());
        let (client, masp_tx_sender) = test_client(2.into());
        let io = StdIo;
        let progress = DefaultTracker::new(&io);
        let vk = ExtendedFullViewingKey::from(
            ExtendedViewingKey::from_str(AA_VIEWING_KEY).expect("Test failed"),
        )
        .fvk
        .vk;
        masp_tx_sender.send(None).expect("Test failed");

        // we first test that with no retries, a fetching failure
        // stops process
        let result = shielded_ctx
            .fetch(
                TestingMaspClient::new(&client),
                &progress,
                None,
                None,
                RetryStrategy::Times(1),
                0,
                &[],
                &[vk],
            )
            .await
            .unwrap_err();
        match result {
            Error::Other(msg) => assert_eq!(
                msg.as_str(),
                "After retrying, could not fetch all MASP txs."
            ),
            other => panic!("{:?} does not match Error::Other(_)", other),
        }

        // We now have a fetch failure followed by two successful
        // masp txs from the same block.
        let masp_tx = arbitrary_masp_tx();
        masp_tx_sender.send(None).expect("Test failed");
        masp_tx_sender
            .send(Some((
                IndexedTx {
                    height: 1.into(),
                    index: TxIndex(1),
                },
                vec![masp_tx.clone()],
            )))
            .expect("Test failed");
        masp_tx_sender
            .send(Some((
                IndexedTx {
                    height: 1.into(),
                    index: TxIndex(2),
                },
                vec![masp_tx.clone()],
            )))
            .expect("Test failed");

        // This should complete successfully
        shielded_ctx
            .fetch(
                TestingMaspClient::new(&client),
                &progress,
                None,
                None,
                RetryStrategy::Times(2),
                0,
                &[],
                &[vk],
            )
            .await
            .expect("Test failed");

        shielded_ctx.load_confirmed().await.expect("Test failed");
        let keys = shielded_ctx
            .tx_note_map
            .keys()
            .cloned()
            .collect::<BTreeSet<_>>();
        let expected = BTreeSet::from([
            IndexedTx {
                height: 1.into(),
                index: TxIndex(1),
            },
            IndexedTx {
                height: 1.into(),
                index: TxIndex(2),
            },
        ]);

        assert_eq!(keys, expected);
        assert_eq!(
            *shielded_ctx.vk_heights[&vk].as_ref().unwrap(),
            IndexedTx {
                height: 1.into(),
                index: TxIndex(2),
            }
        );
        assert_eq!(shielded_ctx.note_map.len(), 2);
    }

    /// Test that upon each retry, we either resume from the
    /// latest height that had been previously stored in the
    /// `tx_note_map`, or from the minimum height stored in
    /// `vk_heights`.
    #[test]
    fn test_min_height_to_sync_from() {
        let temp_dir = tempdir().unwrap();
        let mut shielded_ctx =
            FsShieldedUtils::new(temp_dir.path().to_path_buf());

        let vk = ExtendedFullViewingKey::from(
            ExtendedViewingKey::from_str(AA_VIEWING_KEY).expect("Test failed"),
        )
        .fvk
        .vk;

        // pretend we start with a tx observed at height 4 whose
        // notes cannot be decrypted with `vk`
        shielded_ctx.tx_note_map.insert(
            IndexedTx {
                height: 4.into(),
                index: TxIndex(0),
            },
            0,
        );

        // the min height here should be 1, since
        // this vk hasn't decrypted any note yet
        shielded_ctx.vk_heights.insert(vk, None);

        let height = shielded_ctx.min_height_to_sync_from().unwrap();
        assert_eq!(height, BlockHeight(1));

        // let's bump the vk height past 4
        *shielded_ctx.vk_heights.get_mut(&vk).unwrap() = Some(IndexedTx {
            height: 6.into(),
            index: TxIndex(0),
        });

        // the min height should now be 4
        let height = shielded_ctx.min_height_to_sync_from().unwrap();
        assert_eq!(height, BlockHeight(4));

        // and now we bump the last seen tx to height 8
        shielded_ctx.tx_note_map.insert(
            IndexedTx {
                height: 8.into(),
                index: TxIndex(0),
            },
            1,
        );

        // the min height should now be 6
        let height = shielded_ctx.min_height_to_sync_from().unwrap();
        assert_eq!(height, BlockHeight(6));
    }

    /// Test that the progress tracker correctly keeps
    /// track of how many blocks there are left to fetch
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_left_to_fetch() {
        let temp_dir = tempdir().unwrap();
        let mut shielded_ctx =
            FsShieldedUtils::new(temp_dir.path().to_path_buf());
        let (client, masp_tx_sender) = test_client(2.into());
        let io = StdIo;
        let progress = DefaultTracker::new(&io);
        let vk = ExtendedFullViewingKey::from(
            ExtendedViewingKey::from_str(AA_VIEWING_KEY).expect("Test failed"),
        )
        .fvk
        .vk;
        let masp_tx = arbitrary_masp_tx();

        // first fetch no blocks
        masp_tx_sender.send(None).expect("Test failed");
        shielded_ctx
            .fetch(
                TestingMaspClient::new(&client),
                &progress,
                None,
                None,
                RetryStrategy::Times(1),
                0,
                &[],
                &[vk],
            )
            .await
            .unwrap_err();
        assert_eq!(progress.left_to_fetch(), 2);

        // fetch one of the two blocks
        masp_tx_sender
            .send(Some((
                IndexedTx {
                    height: 1.into(),
                    index: Default::default(),
                },
                vec![masp_tx.clone()],
            )))
            .expect("Test failed");
        masp_tx_sender.send(None).expect("Test failed");
        shielded_ctx
            .fetch(
                TestingMaspClient::new(&client),
                &progress,
                None,
                None,
                RetryStrategy::Times(1),
                0,
                &[],
                &[vk],
            )
            .await
            .unwrap_err();
        assert_eq!(progress.left_to_fetch(), 1);

        // fetch no blocks
        masp_tx_sender.send(None).expect("Test failed");
        shielded_ctx
            .fetch(
                TestingMaspClient::new(&client),
                &progress,
                None,
                None,
                RetryStrategy::Times(1),
                0,
                &[],
                &[vk],
            )
            .await
            .unwrap_err();
        assert_eq!(progress.left_to_fetch(), 1);

        // fetch no blocks, but increase the latest block height
        // thus the amount left to fetch should increase
        let (client, masp_tx_sender) = test_client(3.into());
        masp_tx_sender.send(None).expect("Test failed");
        shielded_ctx
            .fetch(
                TestingMaspClient::new(&client),
                &progress,
                None,
                None,
                RetryStrategy::Times(1),
                0,
                &[],
                &[vk],
            )
            .await
            .unwrap_err();
        assert_eq!(progress.left_to_fetch(), 2);

        // fetch remaining block
        masp_tx_sender
            .send(Some((
                IndexedTx {
                    height: 2.into(),
                    index: Default::default(),
                },
                vec![masp_tx.clone()],
            )))
            .expect("Test failed");
        masp_tx_sender
            .send(Some((
                IndexedTx {
                    height: 3.into(),
                    index: Default::default(),
                },
                vec![masp_tx.clone()],
            )))
            .expect("Test failed");
        // this should not produce an error since we have fetched
        // all expected blocks
        masp_tx_sender.send(None).expect("Test failed");
        shielded_ctx
            .fetch(
                TestingMaspClient::new(&client),
                &progress,
                None,
                None,
                RetryStrategy::Times(1),
                0,
                &[],
                &[vk],
            )
            .await
            .expect("Test failed");
        assert_eq!(progress.left_to_fetch(), 0);
    }

    /// Test that if we don't scan all fetched notes, they
    /// are persisted in a cache
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_unscanned_cache() {
        let (client, masp_tx_sender) = test_client(2.into());
        let temp_dir = tempdir().unwrap();
        let mut shielded_ctx =
            FsShieldedUtils::new(temp_dir.path().to_path_buf());

        let io = StdIo;
        let progress = TestUnscannedTracker::new(&io);
        let vk = ExtendedFullViewingKey::from(
            ExtendedViewingKey::from_str(AA_VIEWING_KEY).expect("Test failed"),
        )
        .fvk
        .vk;

        // the fetched txs
        let masp_tx = arbitrary_masp_tx();
        masp_tx_sender
            .send(Some((
                IndexedTx {
                    height: 1.into(),
                    index: TxIndex(1),
                },
                vec![masp_tx.clone()],
            )))
            .expect("Test failed");
        masp_tx_sender
            .send(Some((
                IndexedTx {
                    height: 1.into(),
                    index: TxIndex(2),
                },
                vec![masp_tx.clone()],
            )))
            .expect("Test failed");

        shielded_ctx
            .fetch(
                TestingMaspClient::new(&client),
                &progress,
                None,
                None,
                RetryStrategy::Times(2),
                0,
                &[],
                &[vk],
            )
            .await
            .expect("Test failed");

        shielded_ctx.load_confirmed().await.expect("Test failed");
        let keys = shielded_ctx
            .unscanned
            .txs
            .lock()
            .unwrap()
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        let expected = vec![IndexedTx {
            height: 1.into(),
            index: TxIndex(2),
        }];
        assert_eq!(keys, expected);
    }

    /// Test that if fetching gets interrupted,
    /// we persist the fetched notes in a cache
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_fetching_interrupt() {
        let temp_dir = tempdir().unwrap();
        let mut shielded_ctx =
            FsShieldedUtils::new(temp_dir.path().to_path_buf());
        let (client, masp_tx_sender) = test_client(2.into());
        let io = StdIo;
        let progress = DefaultTracker::new(&io);
        let vk = ExtendedFullViewingKey::from(
            ExtendedViewingKey::from_str(AA_VIEWING_KEY).expect("Test failed"),
        )
        .fvk
        .vk;
        let (shutdown_send, shutdown_signal) = testing_shutdown_signal();
        // the fetched txs
        let masp_tx = arbitrary_masp_tx();
        // mock that we have already fetched a note
        let expected = (
            IndexedTx {
                height: 1.into(),
                index: TxIndex(1),
            },
            vec![masp_tx],
        );
        masp_tx_sender
            .send(Some(expected.clone()))
            .expect("Test failed");
        shutdown_send.send(()).expect("Test failed");
        let Error::Interrupt(ref proc) = shielded_ctx
            .fetch_aux(
                TestingMaspClient::new(&client),
                &progress,
                None,
                None,
                RetryStrategy::Forever,
                0,
                &[],
                &[vk],
                shutdown_signal,
            )
            .await
            .expect_err("Test failed")
        else {
            panic!("Test failed")
        };
        assert_eq!(proc, "[Testing::Fetch]");
        shielded_ctx.load_confirmed().await.expect("Test failed");
        let entry = shielded_ctx.unscanned.pop_first().expect("Test failed");
        assert_eq!(entry, expected);
        assert!(shielded_ctx.unscanned.is_empty());
    }
}
