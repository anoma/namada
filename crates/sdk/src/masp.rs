//! MASP verification wrappers.

mod shielded_sync;
#[cfg(test)]
mod test_utils;

use std::cmp::Ordering;
use std::collections::{btree_map, BTreeMap, BTreeSet};
use std::fmt::Debug;

use borsh::{BorshDeserialize, BorshSerialize};
use itertools::Itertools;
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
use masp_primitives::sapling::{
    Diversifier, Node, Note, Nullifier, ViewingKey,
};
use masp_primitives::transaction::builder::{self, *};
use masp_primitives::transaction::components::sapling::builder::{
    RngBuildParams, SaplingMetadata,
};
use masp_primitives::transaction::components::{
    I128Sum, TxOut, U64Sum, ValueSum,
};
use masp_primitives::transaction::fees::fixed::FeeRule;
use masp_primitives::transaction::Transaction;
use masp_primitives::zip32::{
    ExtendedFullViewingKey, ExtendedSpendingKey as MaspExtendedSpendingKey,
};
use masp_proofs::prover::LocalTxProver;
use namada_core::address::Address;
use namada_core::arith::CheckedAdd;
use namada_core::collections::{HashMap, HashSet};
use namada_core::dec::Dec;
use namada_core::ibc::IbcTxDataRefs;
pub use namada_core::masp::*;
use namada_core::storage::{BlockHeight, TxIndex};
use namada_core::time::DateTimeUtc;
use namada_core::uint::Uint;
use namada_events::extend::{
    IbcMaspTxBatchRefs as IbcMaspTxBatchRefsAttr,
    MaspTxBatchRefs as MaspTxBatchRefsAttr,
    MaspTxBlockIndex as MaspTxBlockIndexAttr, ReadFromEventAttributes,
};
use namada_ibc::{decode_message, extract_masp_tx_from_envelope, IbcMessage};
use namada_macros::BorshDeserializer;
#[cfg(feature = "migrations")]
use namada_migrations::*;
pub use namada_token::validation::{
    partial_deauthorize, preload_verifying_keys, PVKs, CONVERT_NAME,
    ENV_VAR_MASP_PARAMS_DIR, OUTPUT_NAME, SPEND_NAME,
};
use namada_token::{self as token, Denomination, MaspDigitPos};
use namada_tx::{IndexedTx, Tx};
use rand::rngs::StdRng;
use rand_core::{CryptoRng, OsRng, RngCore, SeedableRng};
use smooth_operator::checked;
use thiserror::Error;

use crate::error::{Error, QueryError};
use crate::io::{Io, ProgressBar};
pub use crate::masp::shielded_sync::dispatcher::DispatcherCache;
use crate::masp::shielded_sync::utils::MaspClient;
#[cfg(not(target_family = "wasm"))]
pub use crate::masp::shielded_sync::MaspLocalTaskEnv;
pub use crate::masp::shielded_sync::{
    utils, ShieldedSyncConfig, ShieldedSyncConfigBuilder,
};
use crate::queries::Client;
use crate::rpc::{query_conversion, query_denom};
use crate::task_env::TaskEnvironment;
use crate::{
    control_flow, display_line, edisplay_line, query_native_token, rpc,
    MaybeSend, MaybeSync, Namada,
};

/// Randomness seed for MASP integration tests to build proofs with
/// deterministic rng.
pub const ENV_VAR_MASP_TEST_SEED: &str = "NAMADA_MASP_TEST_SEED";

/// The network to use for MASP
const NETWORK: Network = Network;

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

/// The data for a masp fee payment
#[allow(missing_docs)]
#[derive(Debug)]
pub struct MaspFeeData {
    pub sources: Vec<namada_core::masp::ExtendedSpendingKey>,
    pub target: Address,
    pub token: Address,
    pub amount: token::DenominatedAmount,
}

/// The data for a single masp transfer
#[allow(missing_docs)]
#[derive(Debug)]
pub struct MaspTransferData {
    pub source: TransferSource,
    pub target: TransferTarget,
    pub token: Address,
    pub amount: token::DenominatedAmount,
}

// The data for a masp transfer relative to a given source
#[derive(Hash, Eq, PartialEq)]
struct MaspSourceTransferData {
    source: TransferSource,
    token: Address,
}

// The data for a masp transfer relative to a given target
#[derive(Hash, Eq, PartialEq)]
struct MaspTargetTransferData {
    source: TransferSource,
    target: TransferTarget,
    token: Address,
}

/// Data to log masp transactions' errors
#[allow(missing_docs)]
#[derive(Debug)]
pub struct MaspDataLog {
    pub source: Option<TransferSource>,
    pub token: Address,
    pub amount: token::DenominatedAmount,
}

struct MaspTxReorderedData {
    source_data: HashMap<MaspSourceTransferData, token::DenominatedAmount>,
    target_data: HashMap<MaspTargetTransferData, token::DenominatedAmount>,
    denoms: HashMap<Address, Denomination>,
}

// Data about the unspent amounts for any given shielded source coming from the
// spent notes in their posses that have been added to the builder. Can be used
// to either pay fees or to return a change
type Changes = HashMap<namada_core::masp::ExtendedSpendingKey, I128Sum>;

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
#[allow(clippy::large_enum_variant)]
#[derive(Error, Debug)]
pub enum TransferErr {
    /// Build error for masp errors
    #[error("{error}")]
    Build {
        /// The error
        error: builder::Error<std::convert::Infallible>,
        /// The optional associated transfer data for logging purposes
        data: Option<MaspDataLog>,
    },
    /// errors
    #[error("{0}")]
    General(#[from] Error),
}

/// Freeze a Builder into the format necessary for inclusion in a Tx. This is
/// the format used by hardware wallets to validate a MASP Transaction.
struct WalletMap;

impl<P1>
    masp_primitives::transaction::components::sapling::builder::MapBuilder<
        P1,
        MaspExtendedSpendingKey,
        (),
        ExtendedFullViewingKey,
    > for WalletMap
{
    fn map_params(&self, _s: P1) {}

    fn map_key(&self, s: MaspExtendedSpendingKey) -> ExtendedFullViewingKey {
        (&s).into()
    }
}

impl<P1, N1>
    MapBuilder<P1, MaspExtendedSpendingKey, N1, (), ExtendedFullViewingKey, ()>
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

    /// Save a cache of data as part of shielded sync if that
    /// process gets interrupted.
    async fn cache_save(&self, _cache: &DispatcherCache)
    -> std::io::Result<()>;

    /// Load a cache of data as part of shielded sync if that
    /// process gets interrupted.
    async fn cache_load(&self) -> std::io::Result<DispatcherCache>;
}

/// Make a ViewingKey that can view notes encrypted by given ExtendedSpendingKey
pub fn to_viewing_key(esk: &MaspExtendedSpendingKey) -> FullViewingKey {
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
/// target. Returns the unused amounts (change) of delta if any
pub fn is_amount_required(
    src: I128Sum,
    dest: I128Sum,
    normed_delta: I128Sum,
    opt_delta: Option<I128Sum>,
) -> Option<I128Sum> {
    let mut changes = None;
    let gap = dest.clone() - src;

    for (asset_type, value) in gap.components() {
        if *value > 0 && normed_delta[asset_type] > 0 {
            let signed_change_amt =
                checked!(normed_delta[asset_type] - *value).unwrap_or_default();
            let unsigned_change_amt = if signed_change_amt > 0 {
                signed_change_amt
            } else {
                // Even if there's no change we still need to set the return
                // value of this function to be Some so that the caller sees
                // that this note should be used
                0
            };

            let change_amt = I128Sum::from_nonnegative(
                asset_type.to_owned(),
                unsigned_change_amt,
            )
            .expect("Change is guaranteed to be non-negative");
            changes = changes
                .map(|prev| prev + change_amt.clone())
                .or(Some(change_amt));
        }
    }

    // Because of the way conversions are computed, we need an extra step here
    // if the token is not the native one
    if let Some(delta) = opt_delta {
        // Only if this note is going to be used, handle the assets in delta
        // (not normalized) that are not part of dest
        changes = changes.map(|mut chngs| {
            for (delta_asset_type, delta_amt) in delta.components() {
                if !dest.asset_types().contains(delta_asset_type) {
                    let rmng = I128Sum::from_nonnegative(
                        delta_asset_type.to_owned(),
                        *delta_amt,
                    )
                    .expect("Change is guaranteed to be non-negative");
                    chngs += rmng;
                }
            }

            chngs
        });
    }

    changes
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

// A type tracking the notes used to construct a shielded transfer. Used to
// avoid reusing the same notes multiple times which would lead to an invalid
// transaction
type SpentNotesTracker = HashMap<ViewingKey, HashSet<usize>>;

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

/// Maps a shielded tx to the index of its first output note.
pub type TxNoteMap = BTreeMap<IndexedTx, usize>;

/// Maps the note index (in the commitment tree) to a witness
pub type WitnessMap = HashMap<usize, IncrementalWitness<Node>>;

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
    pub witness_map: WitnessMap,
    /// The set of note positions that have been spent
    pub spents: HashSet<usize>,
    /// Maps asset types to their decodings
    pub asset_types: HashMap<AssetType, AssetData>,
    /// Maps note positions to their corresponding viewing keys
    pub vk_map: HashMap<usize, ViewingKey>,
    /// Maps a shielded tx to the index of its first output note.
    pub tx_note_map: TxNoteMap,
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
    pub async fn fetch<M, T>(
        &mut self,
        shutdown_signal: impl control_flow::ShutdownSignal,
        env: impl TaskEnvironment,
        config: ShieldedSyncConfig<M, T>,
        last_query_height: Option<BlockHeight>,
        sks: &[MaspExtendedSpendingKey],
        fvks: &[ViewingKey],
    ) -> Result<(), Error>
    where
        M: MaspClient + Send + Sync + Unpin + 'static,
        T: ProgressBar,
    {
        env.run(|spawner| async move {
            let dispatcher = config.dispatcher(spawner, &self.utils).await;

            if let Some(updated_ctx) = dispatcher
                .run(shutdown_signal, None, last_query_height, sks, fvks)
                .await?
            {
                *self = updated_ctx;
            }

            Ok(())
        })
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
        Ok(maybe_least_synced_vk_height
            .map_or_else(BlockHeight::first, |itx| itx.height))
    }

    #[allow(missing_docs)]
    pub fn save_decrypted_shielded_outputs(
        &mut self,
        vk: &ViewingKey,
        note_pos: usize,
        note: Note,
        pa: masp_primitives::sapling::PaymentAddress,
        memo: MemoBytes,
    ) -> Result<(), Error> {
        // Add this note to list of notes decrypted by this
        // viewing key
        self.pos_map.entry(*vk).or_default().insert(note_pos);
        // Compute the nullifier now to quickly recognize when
        // spent
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
        self.vk_map.insert(note_pos, *vk);
        Ok(())
    }

    #[allow(missing_docs)]
    pub fn save_shielded_spends(&mut self, transactions: &[Transaction]) {
        for stx in transactions {
            for ss in
                stx.sapling_bundle().map_or(&vec![], |x| &x.shielded_spends)
            {
                // If the shielded spend's nullifier is in our map, then target
                // note is rendered unusable
                if let Some(note_pos) = self.nf_map.get(&ss.nullifier) {
                    self.spents.insert(*note_pos);
                }
            }
        }
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
    /// achieve the total value. Updates the changes map.
    #[allow(clippy::too_many_arguments)]
    pub async fn collect_unspent_notes(
        &mut self,
        context: &impl Namada,
        spent_notes: &mut SpentNotesTracker,
        sk: namada_core::masp::ExtendedSpendingKey,
        is_native_token: bool,
        target: I128Sum,
        target_epoch: MaspEpoch,
        changes: &mut Changes,
    ) -> Result<
        (
            I128Sum,
            Vec<(Diversifier, Note, MerklePath<Node>)>,
            Conversions,
        ),
        Error,
    > {
        let vk = &to_viewing_key(&sk.into()).vk;
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
                // Skip spend notes already used in this transaction
                if spent_notes
                    .get(vk)
                    .is_some_and(|set| set.contains(note_idx))
                {
                    continue;
                }
                // No more transaction inputs are required once we have met
                // the target amount
                if normed_val_acc >= target {
                    break;
                }
                // Spent notes from the shielded context (i.e. from previous
                // transactions) cannot contribute a new transaction's pool
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

                let opt_delta = if is_native_token {
                    None
                } else {
                    Some(contr.clone())
                };
                // Use this note only if it brings us closer to our target
                if let Some(change) = is_amount_required(
                    normed_val_acc.clone(),
                    target.clone(),
                    normed_contr.clone(),
                    opt_delta,
                ) {
                    // Be sure to record the conversions used in computing
                    // accumulated value
                    val_acc += contr;
                    normed_val_acc += normed_contr;

                    // Update the changes
                    changes
                        .entry(sk)
                        .and_modify(|amt| *amt += &change)
                        .or_insert(change);

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
                    // Append the note the list of used ones
                    spent_notes
                        .entry(vk.to_owned())
                        .and_modify(|set| {
                            set.insert(*note_idx);
                        })
                        .or_insert([*note_idx].into_iter().collect());
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
        data: Vec<MaspTransferData>,
        fee_data: Option<MaspFeeData>,
        update_ctx: bool,
    ) -> Result<Option<ShieldedTransfer>, TransferErr> {
        // Try to get a seed from env var, if any.
        #[allow(unused_mut)]
        let mut rng = StdRng::from_rng(OsRng).unwrap();
        #[cfg(feature = "testing")]
        let mut rng = if let Ok(seed) = std::env::var(ENV_VAR_MASP_TEST_SEED)
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

        // TODO: if the user requested the default expiration, there might be a
        // small discrepancy between the datetime we calculate here and the one
        // we set for the transaction. This should be small enough to not cause
        // any issue, in case refactor this function to request the precise
        // datetime to the caller
        let expiration_height: u32 =
            match context.tx_builder().expiration.to_datetime() {
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

                    let max_block_time =
                        crate::rpc::query_max_block_time_estimate(context)
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
                    // NOTE: The masp library doesn't support optional
                    // expiration so we set the max to mimic
                    // a never-expiring tx. We also need to
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
        // Determine epoch in which to submit potential shielded transaction
        let epoch = rpc::query_masp_epoch(context.client()).await?;

        let mut notes_tracker = SpentNotesTracker::new();
        {
            // Load the current shielded context given
            // the spending key we possess
            let mut shielded = context.shielded_mut().await;
            let _ = shielded.load().await;
        }

        let Some(MaspTxReorderedData {
            source_data,
            target_data,
            mut denoms,
        }) = Self::reorder_data_for_masp_transfer(context, data).await?
        else {
            // No shielded components are needed when neither source nor
            // destination are shielded
            return Ok(None);
        };
        let mut changes = Changes::default();

        for (MaspSourceTransferData { source, token }, amount) in &source_data {
            Self::add_inputs(
                context,
                &mut builder,
                source,
                token,
                amount,
                epoch,
                &denoms,
                &mut notes_tracker,
                &mut changes,
            )
            .await?;
        }

        for (
            MaspTargetTransferData {
                source,
                target,
                token,
            },
            amount,
        ) in target_data
        {
            Self::add_outputs(
                context,
                &mut builder,
                source,
                &target,
                token,
                amount,
                epoch,
                &denoms,
            )
            .await?;
        }

        // Collect the fees if needed
        if let Some(MaspFeeData {
            sources,
            target,
            token,
            amount,
        }) = fee_data
        {
            Self::add_fees(
                context,
                &mut builder,
                &source_data,
                sources,
                &target,
                &token,
                &amount,
                epoch,
                &mut denoms,
                &mut notes_tracker,
                &mut changes,
            )
            .await?;
        }

        // Finally, add outputs representing the change from this payment.
        Self::add_changes(&mut builder, changes)?;

        let builder_clone = builder.clone().map_builder(WalletMap);
        // Build and return the constructed transaction
        #[cfg(not(feature = "testing"))]
        let prover = context.shielded().await.utils.local_tx_prover();
        #[cfg(feature = "testing")]
        let prover = testing::MockTxProver(std::sync::Mutex::new(OsRng));
        let (masp_tx, metadata) = builder
            .build(
                &prover,
                &FeeRule::non_standard(U64Sum::zero()),
                &mut rng,
                &mut RngBuildParams::new(OsRng),
            )
            .map_err(|error| TransferErr::Build { error, data: None })?;

        if update_ctx {
            // Cache the generated transfer
            let mut shielded_ctx = context.shielded_mut().await;
            shielded_ctx
                .pre_cache_transaction(std::slice::from_ref(&masp_tx))
                .await?;
        }

        Ok(Some(ShieldedTransfer {
            builder: builder_clone,
            masp_tx,
            metadata,
            epoch,
        }))
    }

    // Group all the information for every source/token and target/token couple,
    // and extract the denominations for all the tokens involved (expect the one
    // involved in the fees if needed). This step is required so that we can
    // collect the amount required for every couple and pass it to the
    // appropriate function so that notes can be collected based on the correct
    // amount.
    async fn reorder_data_for_masp_transfer(
        context: &impl Namada,
        data: Vec<MaspTransferData>,
    ) -> Result<Option<MaspTxReorderedData>, TransferErr> {
        let mut source_data =
            HashMap::<MaspSourceTransferData, token::DenominatedAmount>::new();
        let mut target_data =
            HashMap::<MaspTargetTransferData, token::DenominatedAmount>::new();
        let mut denoms = HashMap::new();

        for MaspTransferData {
            source,
            target,
            token,
            amount,
        } in data
        {
            let spending_key = source.spending_key();
            let payment_address = target.payment_address();
            // No shielded components are needed when neither source nor
            // destination are shielded
            if spending_key.is_none() && payment_address.is_none() {
                return Ok(None);
            }

            if denoms.get(&token).is_none() {
                if let Some(denom) = query_denom(context.client(), &token).await
                {
                    denoms.insert(token.clone(), denom);
                } else {
                    return Err(TransferErr::General(Error::from(
                        QueryError::General(format!(
                            "denomination for token {token}"
                        )),
                    )));
                };
            }

            let key = MaspSourceTransferData {
                source: source.clone(),
                token: token.clone(),
            };
            match source_data.get_mut(&key) {
                Some(prev_amount) => {
                    *prev_amount = checked!(prev_amount.to_owned() + amount)
                        .map_err(|e| TransferErr::General(e.into()))?;
                }
                None => {
                    source_data.insert(key, amount);
                }
            }

            let key = MaspTargetTransferData {
                source,
                target,
                token,
            };
            match target_data.get_mut(&key) {
                Some(prev_amount) => {
                    *prev_amount = checked!(prev_amount.to_owned() + amount)
                        .map_err(|e| TransferErr::General(e.into()))?;
                }
                None => {
                    target_data.insert(key, amount);
                }
            }
        }

        Ok(Some(MaspTxReorderedData {
            source_data,
            target_data,
            denoms,
        }))
    }

    // Add the necessary transaction inputs to the builder.
    #[allow(clippy::too_many_arguments)]
    async fn add_inputs(
        context: &impl Namada,
        builder: &mut Builder<Network>,
        source: &TransferSource,
        token: &Address,
        amount: &token::DenominatedAmount,
        epoch: MaspEpoch,
        denoms: &HashMap<Address, Denomination>,
        notes_tracker: &mut SpentNotesTracker,
        changes: &mut Changes,
    ) -> Result<Option<I128Sum>, TransferErr> {
        // We want to fund our transaction solely from supplied spending key
        let spending_key = source.spending_key();

        // Now we build up the transaction within this object

        // Convert transaction amount into MASP types
        // Ok to unwrap cause we've already seen the token before, the
        // denomination must be there
        let denom = denoms.get(token).unwrap();
        let (asset_types, masp_amount) = {
            let mut shielded = context.shielded_mut().await;
            // Do the actual conversion to an asset type
            let amount = shielded
                .convert_namada_amount_to_masp(
                    context.client(),
                    epoch,
                    token,
                    denom.to_owned(),
                    amount.amount(),
                )
                .await?;
            // Make sure to save any decodings of the asset types used so
            // that balance queries involving them are
            // successful
            let _ = shielded.save().await;
            amount
        };

        // If there are shielded inputs
        let added_amt = if let Some(sk) = spending_key {
            let is_native_token =
                &query_native_token(context.client()).await? == token;
            // Locate unspent notes that can help us meet the transaction
            // amount
            let (added_amount, unspent_notes, used_convs) = context
                .shielded_mut()
                .await
                .collect_unspent_notes(
                    context,
                    notes_tracker,
                    sk,
                    is_native_token,
                    I128Sum::from_sum(masp_amount),
                    epoch,
                    changes,
                )
                .await?;
            // Commit the notes found to our transaction
            for (diversifier, note, merkle_path) in unspent_notes {
                builder
                    .add_sapling_spend(
                        sk.into(),
                        diversifier,
                        note,
                        merkle_path,
                    )
                    .map_err(|e| TransferErr::Build {
                        error: builder::Error::SaplingBuild(e),
                        data: None,
                    })?;
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
                        .map_err(|e| TransferErr::Build {
                            error: builder::Error::SaplingBuild(e),
                            data: None,
                        })?;
                }
            }

            Some(added_amount)
        } else {
            // We add a dummy UTXO to our transaction, but only the source
            // of the parent Transfer object is used to
            // validate fund availability
            let script = source
                .t_addr_data()
                .ok_or_else(|| {
                    Error::Other(
                        "source address should be transparent".to_string(),
                    )
                })?
                .taddress();

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
                        .map_err(|e| TransferErr::Build {
                            error: builder::Error::TransparentBuild(e),
                            data: None,
                        })?;
                }
            }

            None
        };

        Ok(added_amt)
    }

    // Add the necessary transaction outputs to the builder
    #[allow(clippy::too_many_arguments)]
    async fn add_outputs(
        context: &impl Namada,
        builder: &mut Builder<Network>,
        source: TransferSource,
        target: &TransferTarget,
        token: Address,
        amount: token::DenominatedAmount,
        epoch: MaspEpoch,
        denoms: &HashMap<Address, Denomination>,
    ) -> Result<(), TransferErr> {
        // Anotate the asset type in the value balance with its decoding in
        // order to facilitate cross-epoch computations
        let value_balance = context
            .shielded_mut()
            .await
            .decode_sum(context.client(), builder.value_balance())
            .await;

        let payment_address = target.payment_address();

        // This indicates how many more assets need to be sent to the
        // receiver in order to satisfy the requested transfer
        // amount.
        let mut rem_amount = amount.amount().raw_amount().0;

        // Ok to unwrap cause we've already seen the token before, the
        // denomination must be there
        let denom = denoms.get(&token).unwrap();

        // Now handle the outputs of this transaction
        // Loop through the value balance components and see which
        // ones can be given to the receiver
        for ((asset_type, decoded), val) in value_balance.components() {
            let rem_amount = &mut rem_amount[decoded.position as usize];
            // Only asset types with the correct token can contribute. But
            // there must be a demonstrated need for it.
            if decoded.token == token
                && &decoded.denom == denom
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
                // If we are sending to a shielded address, we need the outgoing
                // viewing key in the following computations.
                let ovk_opt = source
                    .spending_key()
                    .map(|x| MaspExtendedSpendingKey::from(x).expsk.ovk);
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
                            MemoBytes::empty(),
                        )
                        .map_err(|e| TransferErr::Build {
                            error: builder::Error::SaplingBuild(e),
                            data: None,
                        })?;
                } else if let Some(t_addr_data) = target.t_addr_data() {
                    // If there is a transparent output
                    builder
                        .add_transparent_output(
                            &t_addr_data.taddress(),
                            *asset_type,
                            contr,
                        )
                        .map_err(|e| TransferErr::Build {
                            error: builder::Error::TransparentBuild(e),
                            data: None,
                        })?;
                } else {
                    return Result::Err(TransferErr::from(Error::Other(
                        "transaction target must be a payment address or \
                         Namada address or IBC address"
                            .to_string(),
                    )));
                }
                // Lower what is required of the remaining contribution
                *rem_amount -= contr;
            }
        }

        // Nothing must remain to be included in output
        if rem_amount != [0; 4] {
            let (asset_types, _) = {
                let mut shielded = context.shielded_mut().await;
                // Do the actual conversion to an asset type
                let amount = shielded
                    .convert_namada_amount_to_masp(
                        context.client(),
                        epoch,
                        &token,
                        denom.to_owned(),
                        amount.amount(),
                    )
                    .await?;
                // Make sure to save any decodings of the asset types used so
                // that balance queries involving them are
                // successful
                let _ = shielded.save().await;
                amount
            };

            // Convert the shortfall into a I128Sum
            let mut shortfall = I128Sum::zero();
            for (asset_type, val) in asset_types.iter().zip(rem_amount) {
                shortfall += I128Sum::from_pair(*asset_type, val.into());
            }
            // Return an insufficient funds error
            return Result::Err(TransferErr::Build {
                error: builder::Error::InsufficientFunds(shortfall),
                data: Some(MaspDataLog {
                    source: Some(source),
                    token,
                    amount,
                }),
            });
        }

        Ok(())
    }

    // Add the necessary note to include a masp fee payment in the transaction.
    // Funds are gathered in the following order:
    //
    // 1. From the residual values of the already included spend notes (i.e.
    //    changes)
    // 2. From new spend notes of the transaction's sources
    // 3. From new spend notes of the optional gas spending keys
    #[allow(clippy::too_many_arguments)]
    async fn add_fees(
        context: &impl Namada,
        builder: &mut Builder<Network>,
        source_data: &HashMap<MaspSourceTransferData, token::DenominatedAmount>,
        sources: Vec<namada_core::masp::ExtendedSpendingKey>,
        target: &Address,
        token: &Address,
        amount: &token::DenominatedAmount,
        epoch: MaspEpoch,
        denoms: &mut HashMap<Address, Denomination>,
        notes_tracker: &mut SpentNotesTracker,
        changes: &mut Changes,
    ) -> Result<(), TransferErr> {
        if denoms.get(token).is_none() {
            if let Some(denom) = query_denom(context.client(), token).await {
                denoms.insert(token.to_owned(), denom);
            } else {
                return Err(TransferErr::General(Error::from(
                    QueryError::General(format!(
                        "denomination for token {token}"
                    )),
                )));
            };
        }

        let raw_amount = amount.amount().raw_amount().0;
        let (asset_types, _) = {
            let mut shielded = context.shielded_mut().await;
            // Do the actual conversion to an asset type
            let (asset_types, amount) = shielded
                .convert_namada_amount_to_masp(
                    context.client(),
                    epoch,
                    token,
                    // Safe to unwrap
                    denoms.get(token).unwrap().to_owned(),
                    amount.amount(),
                )
                .await?;
            // Make sure to save any decodings of the asset types used so
            // that balance queries involving them are
            // successful
            let _ = shielded.save().await;
            (asset_types, amount)
        };

        let mut fees = I128Sum::zero();
        // Convert the shortfall into a I128Sum
        for (asset_type, val) in asset_types.iter().zip(raw_amount) {
            fees += I128Sum::from_nonnegative(*asset_type, val.into())
                .map_err(|()| {
                    TransferErr::General(Error::Other(
                        "Fee amount is expected expected to be non-negative"
                            .to_string(),
                    ))
                })?;
        }

        // 1. Try to use the change to pay fees
        let mut temp_changes = Changes::default();

        for (sp, changes) in changes.iter() {
            for (asset_type, change) in changes.components() {
                for (_, fee_amt) in fees
                    .clone()
                    .components()
                    .filter(|(axt, _)| *axt == asset_type)
                {
                    // Get the minimum between the available change and
                    // the due fee
                    let output_amt = I128Sum::from_nonnegative(
                        asset_type.to_owned(),
                        *change.min(fee_amt),
                    )
                    .map_err(|()| {
                        TransferErr::General(Error::Other(
                            "Fee amount is expected to be non-negative"
                                .to_string(),
                        ))
                    })?;
                    let denominated_output_amt = context
                        .shielded_mut()
                        .await
                        .convert_masp_amount_to_namada(
                            context.client(),
                            // Safe to unwrap
                            denoms.get(token).unwrap().to_owned(),
                            output_amt.clone(),
                        )
                        .await?;

                    Self::add_outputs(
                        context,
                        builder,
                        TransferSource::ExtendedSpendingKey(sp.to_owned()),
                        &TransferTarget::Address(target.clone()),
                        token.clone(),
                        denominated_output_amt,
                        epoch,
                        denoms,
                    )
                    .await?;

                    fees -= &output_amt;
                    // Update the changes
                    temp_changes
                        .entry(*sp)
                        .and_modify(|amt| *amt += &output_amt)
                        .or_insert(output_amt);
                }
            }

            if fees.is_zero() {
                break;
            }
        }

        // Decrease the changes by the amounts used for fee payment
        for (sp, temp_changes) in temp_changes.iter() {
            for (asset_type, temp_change) in temp_changes.components() {
                let output_amt = I128Sum::from_nonnegative(
                    asset_type.to_owned(),
                    *temp_change,
                )
                .map_err(|()| {
                    TransferErr::General(Error::Other(
                        "Fee amount is expected expected to be non-negative"
                            .to_string(),
                    ))
                })?;

                // Entry is guaranteed to be in the map
                changes.entry(*sp).and_modify(|amt| *amt -= &output_amt);
            }
        }

        if !fees.is_zero() {
            // 2. Look for unused spent notes of the sources and the optional
            //    gas spending keys (sources first)
            for fee_source in
                source_data.iter().map(|(src, _)| src.source.clone()).chain(
                    sources
                        .into_iter()
                        .map(TransferSource::ExtendedSpendingKey),
                )
            {
                for (asset_type, fee_amt) in fees.clone().components() {
                    let input_amt = I128Sum::from_nonnegative(
                        asset_type.to_owned(),
                        *fee_amt,
                    )
                    .map_err(|()| {
                        TransferErr::General(Error::Other(
                            "Fee amount is expected expected to be \
                             non-negative"
                                .to_string(),
                        ))
                    })?;
                    let denominated_fee = context
                        .shielded_mut()
                        .await
                        .convert_masp_amount_to_namada(
                            context.client(),
                            // Safe to unwrap
                            denoms.get(token).unwrap().to_owned(),
                            input_amt.clone(),
                        )
                        .await?;

                    let Some(found_amt) = Self::add_inputs(
                        context,
                        builder,
                        &fee_source,
                        token,
                        &denominated_fee,
                        epoch,
                        denoms,
                        notes_tracker,
                        changes,
                    )
                    .await?
                    else {
                        continue;
                    };
                    // Pick the minimum between the due fee and the amount found
                    let output_amt = match found_amt.partial_cmp(&input_amt) {
                        None | Some(Ordering::Less) => found_amt,
                        _ => input_amt.clone(),
                    };
                    let denom_amt = context
                        .shielded_mut()
                        .await
                        .convert_masp_amount_to_namada(
                            context.client(),
                            // Safe to unwrap
                            denoms.get(token).unwrap().to_owned(),
                            output_amt.clone(),
                        )
                        .await?;

                    Self::add_outputs(
                        context,
                        builder,
                        fee_source.clone(),
                        &TransferTarget::Address(target.clone()),
                        token.clone(),
                        denom_amt,
                        epoch,
                        denoms,
                    )
                    .await?;

                    fees -= &output_amt;
                }

                if fees.is_zero() {
                    break;
                }
            }
        }

        if !fees.is_zero() {
            return Result::Err(TransferErr::Build {
                error: builder::Error::InsufficientFunds(fees),
                data: Some(MaspDataLog {
                    source: None,
                    token: token.to_owned(),
                    amount: *amount,
                }),
            });
        }

        Ok(())
    }

    // Consumes the changes and adds them back to the original sources to
    // balance the transaction. This function has to be called after
    // `add_fees` cause we might have some change coming from there too
    #[allow(clippy::result_large_err)]
    fn add_changes(
        builder: &mut Builder<Network>,
        changes: Changes,
    ) -> Result<(), TransferErr> {
        for (sp, changes) in changes.into_iter() {
            for (asset_type, amt) in changes.components() {
                if let Ordering::Greater = amt.cmp(&0) {
                    let sk = MaspExtendedSpendingKey::from(sp.to_owned());
                    // Send the change in this asset type back to the sender
                    builder
                        .add_sapling_output(
                            Some(sk.expsk.ovk),
                            sk.default_address().1,
                            *asset_type,
                            *amt as u64,
                            MemoBytes::empty(),
                        )
                        .map_err(|e| TransferErr::Build {
                            error: builder::Error::SaplingBuild(e),
                            data: None,
                        })?;
                }
            }
        }

        // Final safety check on the value balance to verify that the
        // transaction is balanced
        let value_balance = builder.value_balance();
        if !value_balance.is_zero() {
            return Result::Err(TransferErr::Build {
                error: builder::Error::InsufficientFunds(value_balance),
                data: None,
            });
        }

        Ok(())
    }

    // Updates the internal state with the data of the newly generated
    // transaction. More specifically invalidate the spent notes, but do not
    // cache the newly produced output descriptions and therefore the merkle
    // tree
    async fn pre_cache_transaction(
        &mut self,
        masp_txs: &[Transaction],
    ) -> Result<(), Error> {
        self.save_shielded_spends(masp_txs);

        // Save the speculative state for future usage
        self.sync_status = ContextSyncStatus::Speculative;
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

    /// Convert Namada amount and token type to MASP equivalents
    async fn convert_namada_amount_to_masp<C: Client + Sync>(
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

    /// Convert MASP amount to Namada equivalent
    async fn convert_masp_amount_to_namada<C: Client + Sync>(
        &mut self,
        client: &C,
        denom: Denomination,
        amt: I128Sum,
    ) -> Result<token::DenominatedAmount, Error> {
        let mut amount = token::Amount::zero();
        let value_sum = self.decode_sum(client, amt).await;

        for ((_, decoded), val) in value_sum.components() {
            let positioned_amt = token::Amount::from_masp_denominated_i128(
                *val,
                decoded.position,
            )
            .unwrap_or_default();
            amount = checked!(amount + positioned_amt)?;
        }

        Ok(token::DenominatedAmount::new(amount, denom))
    }
}

/// Extract the relevant shield portions of a [`Tx`], if any.
fn extract_masp_tx(
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
            match tx.get_masp_section(hash).cloned().ok_or_else(|| {
                Error::Other("Missing expected masp transaction".to_string())
            }) {
                Ok(transaction) => {
                    acc.push(transaction);
                    Ok(acc)
                }
                Err(e) => Err(e),
            }
        })
}

/// Extract the relevant shield portions from the IBC messages in [`Tx`]
fn extract_masp_tx_from_ibc_message(
    tx: &Tx,
) -> Result<Vec<Transaction>, Error> {
    let mut masp_txs = Vec::new();
    for cmt in &tx.header.batch {
        let tx_data = tx.data(cmt).ok_or_else(|| {
            Error::Other("Missing transaction data".to_string())
        })?;
        let ibc_msg = decode_message::<token::Transfer>(&tx_data)
            .map_err(|_| Error::Other("Invalid IBC message".to_string()))?;
        if let IbcMessage::Envelope(ref envelope) = ibc_msg {
            if let Some(masp_tx) = extract_masp_tx_from_envelope(envelope) {
                masp_txs.push(masp_tx);
            }
        }
    }
    if !masp_txs.is_empty() {
        Ok(masp_txs)
    } else {
        Err(Error::Other(
            "IBC message doesn't have masp transaction".to_string(),
        ))
    }
}

// Retrieves all the indexes at the specified height which refer
// to a valid masp transaction. If an index is given, it filters only the
// transactions with an index equal or greater to the provided one.
async fn get_indexed_masp_events_at_height<C: Client + Sync>(
    client: &C,
    height: BlockHeight,
    first_idx_to_query: Option<TxIndex>,
) -> Result<
    Option<Vec<(TxIndex, Option<MaspTxRefs>, Option<IbcTxDataRefs>)>>,
    Error,
> {
    let first_idx_to_query = first_idx_to_query.unwrap_or_default();

    Ok(client
        .block_results(height.0)
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
                            .ok();
                        let ibc_tx_data_refs =
                            IbcMaspTxBatchRefsAttr::read_from_event_attributes(
                                &event.attributes,
                            )
                            .ok();

                        Some((tx_index, masp_section_refs, ibc_tx_data_refs))
                    } else {
                        None
                    }
                })
                .collect::<Vec<_>>()
        }))
}

#[cfg(test)]
mod tests {
    use masp_proofs::bls12_381::Bls12;

    use super::*;

    /// quick and dirty test. will fail on size check
    #[test]
    #[should_panic(expected = "parameter file size is not correct")]
    fn test_wrong_masp_params() {
        use std::io::Write;

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

        std::env::set_var(ENV_VAR_MASP_PARAMS_DIR, tempdir.as_os_str());
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
        use masp_proofs::bls12_381::Scalar;

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

        std::env::set_var(ENV_VAR_MASP_PARAMS_DIR, tempdir.as_os_str());
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

    use masp_primitives::consensus::testing::arb_height;
    use masp_primitives::constants::SPENDING_KEY_GENERATOR;
    use masp_primitives::group::GroupEncoding;
    use masp_primitives::sapling::note_encryption::{
        try_sapling_note_decryption, PreparedIncomingViewingKey,
    };
    use masp_primitives::sapling::prover::TxProver;
    use masp_primitives::sapling::redjubjub::{PublicKey, Signature};
    use masp_primitives::sapling::{ProofGenerationKey, Rseed};
    use masp_primitives::transaction::components::sapling::builder::StoredBuildParams;
    use masp_primitives::transaction::components::{
        OutputDescription, GROTH_PROOF_SIZE,
    };
    use masp_primitives::transaction::{
        Authorization, Authorized, TransparentAddress,
    };
    use masp_proofs::bellman::groth16::Proof;
    use masp_proofs::bls12_381;
    use masp_proofs::bls12_381::{Bls12, G1Affine, G2Affine};
    use namada_core::address::testing::arb_non_internal_address;
    use namada_token::{DenominatedAmount, Transfer};
    use proptest::prelude::*;
    use proptest::sample::SizeRange;
    use proptest::test_runner::TestRng;
    use proptest::{collection, option, prop_compose};

    use super::*;
    use crate::address::testing::arb_address;
    use crate::address::MASP;
    use crate::masp_primitives::consensus::BranchId;
    use crate::masp_primitives::constants::VALUE_COMMITMENT_RANDOMNESS_GENERATOR;
    use crate::masp_primitives::merkle_tree::FrozenCommitmentTree;
    use crate::masp_primitives::sapling::keys::OutgoingViewingKey;
    use crate::masp_primitives::sapling::redjubjub::PrivateKey;
    use crate::masp_primitives::transaction::components::transparent::testing::arb_transparent_address;
    use crate::token::testing::arb_denomination;

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
            let spending_key = MaspExtendedSpendingKey::master(spending_key_seed.as_ref());

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
        ) -> (MaspExtendedSpendingKey, Diversifier, Note, Node) {
            let mut spending_key_seed = [0; 32];
            rng.fill_bytes(&mut spending_key_seed);
            let spending_key = MaspExtendedSpendingKey::master(spending_key_seed.as_ref());

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
        ) -> Vec<(MaspExtendedSpendingKey, Diversifier, Note, Node)> {
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
            input_data in collection::vec((any::<bool>(), arb_non_internal_address()), assets.len() * MAX_SPLITS),
            output_data in collection::vec((any::<bool>(), arb_non_internal_address()), assets.len() * MAX_SPLITS),
            assets in Just(assets),
        ) -> (
            Transfer,
            Builder::<Network>,
            HashMap<AssetData, u64>,
        ) {
            // Enable assets to be more easily decoded
            let mut asset_decoder = BTreeMap::new();
            for asset_data in assets.keys() {
                let asset_type = encode_asset_type(
                    asset_data.token.clone(),
                    asset_data.denom,
                    asset_data.position,
                    asset_data.epoch,
                ).unwrap();
                asset_decoder.insert(asset_type, asset_data);
            }
            let mut transfer = Transfer::default();
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
            for ((is_shielded, address), (idx, (esk, div, note, _node))) in
                input_data.into_iter().zip(spend_descriptions.iter().flatten().enumerate())
            {
                // Compute the equivalent transparent movement
                let asset_data = asset_decoder[&note.asset_type];
                let amount = DenominatedAmount::new(
                    token::Amount::from_masp_denominated(note.value, asset_data.position),
                    asset_data.denom,
                );
                // Use either a transparent input or a shielded input
                if is_shielded {
                    builder.add_sapling_spend(*esk, *div, *note, tree.path(idx)).unwrap();
                    transfer = transfer.debit(MASP, asset_data.token.clone(), amount).unwrap();
                } else {
                    let txout = TxOut {
                        address: TAddrData::Addr(address.clone()).taddress(),
                        asset_type: note.asset_type,
                        value: note.value,
                    };
                    builder.add_transparent_input(txout).unwrap();
                    transfer = transfer.debit(address, asset_data.token.clone(), amount).unwrap();
                }
            }
            for ((is_shielded, address), (ovk, payment_addr, asset_type, value, memo)) in
                output_data.into_iter().zip(output_descriptions.into_iter().flatten())
            {
                // Compute the equivalent transparent movement
                let asset_data = asset_decoder[&asset_type];
                let amount = DenominatedAmount::new(
                    token::Amount::from_masp_denominated(value, asset_data.position),
                    asset_data.denom,
                );
                // Use either a transparent output or a shielded output
                if is_shielded {
                    builder.add_sapling_output(ovk, payment_addr, asset_type, value, memo).unwrap();
                    transfer = transfer.credit(MASP, asset_data.token.clone(), amount).unwrap();
                } else {
                    builder.add_transparent_output(
                        &TAddrData::Addr(address.clone()).taddress(),
                        asset_type,
                        value,
                    ).unwrap();
                    transfer = transfer.credit(address, asset_data.token.clone(), amount).unwrap();
                }
            }
            (transfer, builder, assets.into_iter().map(|(k, v)| (k, v.iter().sum())).collect())
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
        /// Generate an arbitrary MASP shielded transfer
        pub fn arb_shielded_transfer(
            asset_range: impl Into<SizeRange>,
        )(asset_range in Just(asset_range.into()))(
            (mut transfer, builder, asset_types) in arb_shielded_builder(asset_range),
            epoch in arb_masp_epoch(),
            prover_rng in arb_rng().prop_map(TestCsprng),
            mut rng in arb_rng().prop_map(TestCsprng),
            bparams_rng in arb_rng().prop_map(TestCsprng),
        ) -> (Transfer, ShieldedTransfer, HashMap<AssetData, u64>, StoredBuildParams) {
            let mut rng_build_params = RngBuildParams::new(bparams_rng);
            let (masp_tx, metadata) = builder.clone().build(
                &MockTxProver(Mutex::new(prover_rng)),
                &FeeRule::non_standard(U64Sum::zero()),
                &mut rng,
                &mut rng_build_params,
            ).unwrap();
            transfer.shielded_section_hash = Some(masp_tx.txid().into());
            (transfer, ShieldedTransfer {
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
    use std::env;
    use std::fs::{File, OpenOptions};
    use std::io::{Read, Write};
    use std::path::PathBuf;

    use namada_token::validation::{
        get_params_dir, CONVERT_NAME, ENV_VAR_MASP_PARAMS_DIR, OUTPUT_NAME,
        SPEND_NAME,
    };

    use super::*;

    /// Shielded context file name
    const FILE_NAME: &str = "shielded.dat";
    const TMP_FILE_PREFIX: &str = "shielded.tmp";
    const SPECULATIVE_FILE_NAME: &str = "speculative_shielded.dat";
    const SPECULATIVE_TMP_FILE_PREFIX: &str = "speculative_shielded.tmp";
    const CACHE_FILE_NAME: &str = "shielded_sync.cache";
    const CACHE_FILE_TMP_PREFIX: &str = "shielded_sync.cache.tmp";

    #[derive(Debug, BorshSerialize, BorshDeserialize, Clone)]
    /// An implementation of ShieldedUtils for standard filesystems
    pub struct FsShieldedUtils {
        #[borsh(skip)]
        pub(crate) context_dir: PathBuf,
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

        /// Write to a file ensuring that all contents of the file
        /// were written by a single process (in case of multiple
        /// concurrent write attempts).
        ///
        /// N.B. This is not the same as a file lock. If multiple
        /// concurrent writes take place, this code ensures that
        /// the result of exactly one will be persisted.
        ///
        /// N.B. This only truly works if each process uses
        /// to a *unique* tmp file name.
        fn atomic_file_write(
            &self,
            tmp_file_name: impl AsRef<std::path::Path>,
            file_name: impl AsRef<std::path::Path>,
            data: impl BorshSerialize,
        ) -> std::io::Result<()> {
            let tmp_path = self.context_dir.join(&tmp_file_name);
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
                data.serialize(&mut bytes).unwrap_or_else(|e| {
                    panic!(
                        "cannot serialize data to {} with error: {}",
                        file_name.as_ref().to_string_lossy(),
                        e,
                    )
                });
                ctx_file.write_all(&bytes[..])?;
            }
            // Atomically update the old shielded context file with new data.
            // Atomicity is required to prevent other client instances from
            // reading corrupt data.
            std::fs::rename(tmp_path, self.context_dir.join(file_name))
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
            let (tmp_file_pref, file_name) = match ctx.sync_status {
                ContextSyncStatus::Confirmed => (TMP_FILE_PREFIX, FILE_NAME),
                ContextSyncStatus::Speculative => {
                    (SPECULATIVE_TMP_FILE_PREFIX, SPECULATIVE_FILE_NAME)
                }
            };
            let tmp_file_name = {
                let t = tempfile::Builder::new()
                    .prefix(tmp_file_pref)
                    .tempfile()?;
                t.path().file_name().unwrap().to_owned()
            };
            self.atomic_file_write(tmp_file_name, file_name, ctx)?;

            // Remove the speculative file if present since it's state is
            // overruled by the confirmed one we just saved
            if let ContextSyncStatus::Confirmed = ctx.sync_status {
                let _ = std::fs::remove_file(
                    self.context_dir.join(SPECULATIVE_FILE_NAME),
                );
            }

            Ok(())
        }

        async fn cache_save(
            &self,
            cache: &DispatcherCache,
        ) -> std::io::Result<()> {
            let tmp_file_name = {
                let t = tempfile::Builder::new()
                    .prefix(CACHE_FILE_TMP_PREFIX)
                    .tempfile()?;
                t.path().file_name().unwrap().to_owned()
            };

            self.atomic_file_write(tmp_file_name, CACHE_FILE_NAME, cache)
        }

        async fn cache_load(&self) -> std::io::Result<DispatcherCache> {
            let file_name = self.context_dir.join(CACHE_FILE_NAME);
            let mut file = File::open(file_name)?;
            DispatcherCache::try_from_reader(&mut file)
        }
    }
}
