use std::cmp::Ordering;
use std::collections::{btree_map, BTreeMap, BTreeSet};
use std::convert::TryInto;

use borsh::{BorshDeserialize, BorshSerialize};
use borsh_ext::BorshSerializeExt;
use itertools::Either;
use masp_primitives::asset_type::AssetType;
use masp_primitives::consensus::TestNetwork;
use masp_primitives::convert::AllowedConversion;
use masp_primitives::memo::MemoBytes;
use masp_primitives::merkle_tree::{
    CommitmentTree, IncrementalWitness, MerklePath,
};
use masp_primitives::sapling::note_encryption::{
    try_sapling_note_decryption, PreparedIncomingViewingKey,
};
use masp_primitives::sapling::{
    Diversifier, Node, Note, Nullifier, ViewingKey,
};
use masp_primitives::transaction::builder::Builder;
use masp_primitives::transaction::components::{
    I128Sum, OutputDescription, TxOut, U64Sum, ValueSum,
};
use masp_primitives::transaction::fees::fixed::FeeRule;
use masp_primitives::transaction::{
    builder, Authorization, Authorized, Transaction, TransparentAddress,
};
use masp_primitives::zip32::{ExtendedFullViewingKey, ExtendedSpendingKey};
use namada_core::address::{Address, MASP};
use namada_core::collections::{HashMap, HashSet};
use namada_core::masp::{
    encode_asset_type, AssetData, BalanceOwner, ExtendedViewingKey,
    PaymentAddress, TransferSource, TransferTarget,
};
use namada_core::storage::{BlockHeight, Epoch, IndexedTx, TxIndex};
use namada_core::time::{DateTimeUtc, DurationSecs};
use namada_core::token::Amount;
use namada_token::{self as token, Denomination, MaspDigitPos};
use namada_tx::Tx;
use rand_core::OsRng;
use rayon::prelude::*;
use ripemd::Digest as RipemdDigest;
use sha2::Digest;
use tendermint_rpc::query::Query;
use tendermint_rpc::Order;

use crate::error::{Error, PinnedBalanceError, QueryError};
use crate::eth_bridge::token::storage_key::{
    balance_key, is_any_shielded_action_balance_key,
};
use crate::io::Io;
use crate::masp::types::{
    ContextSyncStatus, Conversions, DecryptedData, DecryptedDataCache,
    MaspAmount, MaspChange, ScannedData, ShieldedTransfer, TransactionDelta,
    TransferDelta, TransferErr, Unscanned, WalletMap,
};
use crate::masp::utils::{
    cloned_pair, extract_masp_tx, extract_payload, fetch_channel,
    is_amount_required, to_viewing_key, DefaultTracker,
    ExtractShieldedActionArg, FetchQueueSender, LedgerMaspClient, MaspClient,
    ProgressTracker, RetryStrategy, ShieldedUtils, TaskManager,
};
use crate::masp::NETWORK;
use crate::queries::Client;
use crate::rpc::{
    query_block, query_conversion, query_denom, query_epoch_at_height,
    query_native_token,
};
use crate::{display_line, edisplay_line, rpc, MaybeSend, MaybeSync, Namada};

/// Represents the current state of the shielded pool from the perspective of
/// the chosen viewing keys.
#[derive(BorshSerialize, BorshDeserialize, Debug, Clone)]
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
    /// We cannot update spent notes until all fetched notes have been
    /// decrypted. This temporarily stores the relevant encrypted data in
    /// case syncing is interrupted.
    pub decrypted_note_cache: DecryptedDataCache,
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
            decrypted_note_cache: Default::default(),
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
    pub(crate) async fn update_witness_map<
        'a,
        C: Client,
        IO: Io,
        F: MaspClient<'a, C> + 'a,
    >(
        &mut self,
        client: &'a C,
        io: &IO,
        last_witnessed_tx: IndexedTx,
        last_query_height: BlockHeight,
    ) -> Result<(), Error> {
        let client = F::new(client);
        client
            .update_commitment_tree(
                self,
                io,
                last_witnessed_tx,
                last_query_height,
            )
            .await
    }

    /// Obtain a chronologically-ordered list of all accepted shielded
    /// transactions from a node.
    async fn fetch_shielded_transfers<
        'a,
        C: Client + Sync,
        IO: Io,
        F: MaspClient<'a, C> + 'a,
    >(
        block_sender: FetchQueueSender,
        client: &'a C,
        progress: &impl ProgressTracker<IO>,
        last_indexed_tx: Option<BlockHeight>,
        last_query_height: BlockHeight,
    ) -> Result<(), Error> {
        let client = F::new(client);
        // Fetch all the transactions we do not have yet
        let first_height_to_query =
            last_indexed_tx.map_or_else(|| 1, |last| last.0);
        client
            .fetch_shielded_transfer(
                progress,
                block_sender,
                first_height_to_query,
                last_query_height.0,
            )
            .await
    }

    /// Attempts to decrypt the note in each transaction. Successfully
    /// decrypted notes are associated to the supplied viewing keys. Note
    /// nullifiers are mapped to their originating notes. Note positions are
    /// associated to notes, memos, and diversifiers.
    ///
    /// An append-only idempotent diff of these changes is returned. This
    /// allows this function to be run in parallel. The diffs are collected
    /// and applied by a separate process.
    ///
    /// See <https://zips.z.cash/protocol/protocol.pdf#scan>
    pub(super) fn scan_tx(
        sync_status: ContextSyncStatus,
        indexed_tx: IndexedTx,
        tx_note_map: &BTreeMap<IndexedTx, usize>,
        shielded: &Transaction,
        vk: &ViewingKey,
    ) -> Result<(ScannedData, TransactionDelta), Error> {
        // For tracking the account changes caused by this Transaction
        let mut transaction_delta = TransactionDelta::new();
        let mut scanned_data = ScannedData::default();
        if let ContextSyncStatus::Confirmed = sync_status {
            let mut note_pos =
                *tx_note_map.get(&indexed_tx).ok_or_else(|| {
                    Error::Other(format!(
                        "The scanning algorithm could not find the input {:?} \
                         in the shielded context.",
                        indexed_tx
                    ))
                })?;
            // Listen for notes sent to our viewing keys, only if we are syncing
            // (i.e. in a confirmed status)
            for so in shielded
                .sapling_bundle()
                .map_or(&vec![], |x| &x.shielded_outputs)
            {
                // Let's try to see if this viewing key can decrypt latest
                // note
                let notes = scanned_data.pos_map.entry(*vk).or_default();
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
                    scanned_data.note_map.insert(note_pos, note);
                    scanned_data.memo_map.insert(note_pos, memo);
                    // The payment address' diversifier is required to spend
                    // note
                    scanned_data.div_map.insert(note_pos, *pa.diversifier());
                    scanned_data.nf_map.insert(nf, note_pos);
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
                    scanned_data.vk_map.insert(note_pos, *vk);
                }
                note_pos += 1;
            }
        }
        Ok((scanned_data, transaction_delta))
    }

    /// Parse the cache of decrypted notes:
    /// * nullify notes that have been spent
    /// * update balances of each viewing key
    pub(super) fn nullify_spent_notes(
        &mut self,
        native_token: &Address,
    ) -> Result<(), Error> {
        for ((indexed_tx, _vk), decrypted_data) in
            self.decrypted_note_cache.drain()
        {
            let DecryptedData {
                tx: shielded,
                keys: tx_changed_keys,
                delta: mut transaction_delta,
                epoch,
            } = decrypted_data;

            // Cancel out those of our notes that have been spent
            for ss in shielded
                .sapling_bundle()
                .map_or(&vec![], |x| &x.shielded_spends)
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
                    .map_err(|_| {
                        Error::Other(
                            "found note with invalid value or asset type"
                                .to_string(),
                        )
                    })?;
                }
            }

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
                            if let ContextSyncStatus::Confirmed =
                                self.sync_status
                            {
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

                                let amount = transp_bundle.vin.iter().fold(
                                    Amount::zero(),
                                    |acc, vin| {
                                        acc + Amount::from_u64(vin.value)
                                    },
                                );

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
                                        // Vouts contain the same address, so we
                                        // can
                                        // just examine the first one
                                        transp_bundle.vout.first().is_some_and(
                                            |vout| {
                                                vout.address
                                                    == transp_addr_commit
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
                                "MASP transaction cannot contain both \
                                 transparent inputs and outputs"
                                    .to_string(),
                            ));
                        }
                    }
                }
                None => {
                    // Shielded transfer
                    (MASP, native_token.clone(), Amount::zero())
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
        }
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
        let (_, shielded) = extract_masp_tx(
            &tx,
            ExtractShieldedActionArg::Request::<C>((
                client,
                indexed_tx.height,
                Some(indexed_tx.index),
            )),
            false,
        )
        .await?
        .inner_tx
        .ok_or_else(|| {
            Error::Other("Missing shielded inner portion of pinned tx".into())
        })?;

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
        let rng = if let Ok(seed) = std::env::var(super::ENV_VAR_MASP_TEST_SEED)
            .map_err(|e| Error::Other(e.to_string()))
            .and_then(|seed| {
                let exp_str = format!(
                    "Env var {} must be a u64.",
                    super::ENV_VAR_MASP_TEST_SEED
                );
                let parsed_seed: u64 = std::str::FromStr::from_str(&seed)
                    .map_err(|_| Error::Other(exp_str))?;
                Ok(parsed_seed)
            }) {
            tracing::warn!(
                "UNSAFE: Using a seed from {} env var to build proofs.",
                super::ENV_VAR_MASP_TEST_SEED,
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
            // Return an insufficient funds error
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
        let prover = super::testing::MockTxProver(std::sync::Mutex::new(OsRng));
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
                is_wrapper: false,
            },
            |indexed| IndexedTx {
                height: indexed.height,
                index: indexed.index + 1,
                is_wrapper: false,
            },
        );
        self.sync_status = ContextSyncStatus::Speculative;
        let mut scanned_data = ScannedData::default();
        for vk in vks {
            self.vk_heights.entry(vk).or_default();

            let (scanned, tx_delta) = Self::scan_tx(
                ContextSyncStatus::Speculative,
                indexed_tx,
                &self.tx_note_map,
                masp_tx,
                &vk,
            )?;
            scanned_data.merge(scanned);
            scanned_data.decrypted_note_cache.insert(
                (indexed_tx, vk),
                DecryptedData {
                    tx: masp_tx.clone(),
                    keys: changed_balance_keys.clone(),
                    delta: tx_delta,
                    epoch,
                },
            );
        }
        let mut temp_cache = DecryptedDataCache::default();
        std::mem::swap(&mut temp_cache, &mut self.decrypted_note_cache);
        scanned_data.apply_to(self);
        self.nullify_spent_notes(&native_token)?;
        std::mem::swap(&mut temp_cache, &mut self.decrypted_note_cache);
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

impl<U: ShieldedUtils + Send + Sync> ShieldedContext<U> {
    /// Fetch the current state of the multi-asset shielded pool into a
    /// ShieldedContext
    #[allow(clippy::too_many_arguments)]
    #[cfg(not(target_family = "wasm"))]
    pub async fn fetch<
        'a,
        C: Client + Sync,
        IO: Io + Send + Sync,
        T: ProgressTracker<IO> + Sync,
        M: MaspClient<'a, C> + 'a,
    >(
        &mut self,
        client: &'a C,
        progress: &T,
        retry: RetryStrategy,
        start_query_height: Option<BlockHeight>,
        last_query_height: Option<BlockHeight>,
        _batch_size: u64,
        sks: &[ExtendedSpendingKey],
        fvks: &[ViewingKey],
    ) -> Result<(), Error> {
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

        // add new viewing keys
        for esk in sks {
            let vk = to_viewing_key(esk).vk;
            self.vk_heights.entry(vk).or_default();
        }
        for vk in fvks {
            self.vk_heights.entry(*vk).or_default();
        }
        // Save the context to persist newly added keys
        let _ = self.save().await;

        let native_token = query_native_token(client).await?;
        // the height of the key that is least synced
        let Some(least_idx) = self.vk_heights.values().min().cloned() else {
            return Ok(());
        };
        // the latest block height which has been added to the witness Merkle
        // tree
        let last_witnessed_tx = self.tx_note_map.keys().max().cloned();
        // get the bounds on the block heights to fetch
        let start_height =
            std::cmp::min(last_witnessed_tx, least_idx).map(|idx| idx.height);
        let start_height = start_query_height.or(start_height);
        // Query for the last produced block height
        let last_block_height = query_block(client)
            .await?
            .map(|b| b.height)
            .unwrap_or_else(BlockHeight::first);
        let last_query_height = last_query_height.unwrap_or(last_block_height);
        let last_query_height =
            std::cmp::min(last_query_height, last_block_height);

        // Update the commitment tree and witnesses
        self.update_witness_map::<_, _, M>(
            client,
            progress.io(),
            last_witnessed_tx.unwrap_or_default(),
            last_query_height,
        )
        .await?;
        let vk_heights = self.vk_heights.clone();

        // the task scheduler allows the thread performing trial decryptions to
        // communicate errors and actions (such as saving and updating state).
        // The task manager runs on the main thread and performs the tasks
        // scheduled by the scheduler.
        let (task_scheduler, mut task_manager) =
            TaskManager::<U>::new(self.clone());

        // The main loop that performs
        // * fetching and caching MASP txs in sequence
        // * trial decryption of each note to determine if it is owned by a
        //   viewing key in this context and caching the result.
        // * Nullifying spent notes and updating balances for each viewing key
        // * Regular saving of the context to disk in case of process interrupts
        std::thread::scope(|s| {
            for _ in retry {
                // a stateful channel that communicates notes fetched to the
                // trial decryption process
                let (fetch_send, fetch_recv) =
                    fetch_channel::new(self.unscanned.clone());

                // we trial-decrypt all notes fetched in parallel and schedule
                // the state changes to be applied to the shielded context
                // back on the main thread
                let decryption_handle = s.spawn(|| {
                    // N.B. DON'T GO PANICKING IN HERE. DON'T DO IT. SERIOUSLY.
                    // YOU COULD ACCIDENTALLY FREEZE EVERYTHING
                    let txs = progress.scan(fetch_recv);
                    txs.par_bridge().try_for_each(
                        |(indexed_tx, (epoch, tx, stx))| {
                            let mut scanned_data = ScannedData::default();
                            for (vk, _) in vk_heights
                                .iter()
                                .filter(|(_vk, h)| **h < Some(indexed_tx))
                            {
                                // if this note is in the cache, skip it.
                                if scanned_data
                                    .decrypted_note_cache
                                    .contains(&indexed_tx, vk)
                                {
                                    continue;
                                }
                                // attempt to decrypt the note and get the state
                                // changes
                                let (scanned, tx_delta) = task_scheduler
                                    .scan_tx(
                                        self.sync_status,
                                        indexed_tx,
                                        &self.tx_note_map,
                                        &stx,
                                        vk,
                                    )?;
                                // add the new state changes to the aggregated
                                scanned_data.merge(scanned);
                                // add the note to the cache
                                scanned_data.decrypted_note_cache.insert(
                                    (indexed_tx, *vk),
                                    DecryptedData {
                                        tx: stx.clone(),
                                        keys: tx.clone(),
                                        delta: tx_delta,
                                        epoch,
                                    },
                                );
                            }
                            // save the aggregated state changes
                            task_scheduler.save(scanned_data, indexed_tx);
                            Ok::<(), Error>(())
                        },
                    )?;
                    // signal that the process has finished without error
                    task_scheduler.complete(false);
                    Ok::<(), Error>(())
                });

                // fetch MASP txs and coordinate the state changes from
                // scanning fetched txs asynchronously.
                let (decrypt_res, fetch_res) =
                    tokio::task::block_in_place(|| {
                        tokio::runtime::Handle::current().block_on(async {
                            tokio::join!(
                                task_manager.run(&native_token),
                                Self::fetch_shielded_transfers::<_, _, M>(
                                    fetch_send,
                                    client,
                                    progress,
                                    start_height,
                                    last_query_height,
                                )
                            )
                        })
                    });
                // shut down the scanning thread.
                decryption_handle.join().unwrap()?;
                // if the scanning process errored, return that error here and
                // exit.
                decrypt_res?;

                // if fetching errored, log it. But this is recoverable.
                if let Err(e) = fetch_res {
                    display_line!(
                        progress.io(),
                        "Error encountered while fetching: {}",
                        e.to_string()
                    );
                }

                // if fetching failed for before completing, we restart
                // the fetch process. Otherwise, we can break the loop.
                if progress.left_to_fetch() == 0 {
                    break;
                }
            }
            if progress.left_to_fetch() != 0 {
                Err(Error::Other(
                    "After retrying, could not fetch all MASP txs.".to_string(),
                ))
            } else {
                Ok(())
            }
        })
    }

    /// Obtain the known effects of all accepted shielded and transparent
    /// transactions. If an owner is specified, then restrict the set to only
    /// transactions crediting/debiting the given owner. If token is specified,
    /// then restrict set to only transactions involving the given token.
    #[cfg(not(target_family = "wasm"))]
    pub async fn query_tx_deltas<C: Client + Sync, IO: Io + Sync + Send>(
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
        // Required for filtering out rejected transactions from Tendermint
        // responses
        let block_results = rpc::query_results(client).await?;
        self.fetch::<_, _, _, LedgerMaspClient<C>>(
            client,
            &DefaultTracker::new(io),
            RetryStrategy::Forever,
            None,
            None,
            1,
            &[],
            &fvks,
        )
        .await?;
        // Save the update state so that future fetches can be short-circuited
        let _ = self.save().await;

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
                        // TODO: Check that wrappers shouldn't be considered
                        // here
                        let should_process =
                            !transfers.contains_key(&IndexedTx {
                                height,
                                index: idx,
                                is_wrapper: false,
                            }) && block_results[u64::from(height) as usize]
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
                                IndexedTx {
                                    height,
                                    index: idx,
                                    is_wrapper: false,
                                },
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
}

#[cfg(test)]
mod shielded_ctx_tests {
    use core::str::FromStr;

    use masp_primitives::zip32::ExtendedFullViewingKey;
    use namada_core::address::InternalAddress;
    use namada_core::masp::ExtendedViewingKey;
    use namada_core::storage::Key;
    use tempfile::tempdir;

    use super::*;
    use crate::error::Error;
    use crate::io::StdIo;
    use crate::masp::fs::FsShieldedUtils;
    use crate::masp::test_utils::{
        test_client, TestUnscannedTracker, TestingMaspClient,
    };
    use crate::masp::utils::{DefaultTracker, RetryStrategy};

    // A viewing key derived from A_SPENDING_KEY
    pub const AA_VIEWING_KEY: &str = "zvknam1qqqqqqqqqqqqqq9v0sls5r5de7njx8ehu49pqgmqr9ygelg87l5x8y4s9r0pjlvu6x74w9gjpw856zcu826qesdre628y6tjc26uhgj6d9zqur9l5u3p99d9ggc74ald6s8y3sdtka74qmheyqvdrasqpwyv2fsmxlz57lj4grm2pthzj3sflxc0jx0edrakx3vdcngrfjmru8ywkguru8mxss2uuqxdlglaz6undx5h8w7g70t2es850g48xzdkqay5qs0yw06rtxcpjdve6";

    /// A serialized transaction that will work for testing.
    /// Would love to do this in a less opaque fashion, but
    /// making these things is a misery not worth my time.
    ///
    /// This a tx sending 1 BTC from Albert to Albert's PA
    fn arbitrary_masp_tx() -> (Transaction, BTreeSet<Key>) {
        const ALBERT: &str = "tnam1qxfj3sf6a0meahdu9t6znp05g8zx4dkjtgyn9gfu";
        const BTC: &str = "tnam1qy88jaykzw8tay6svmu6kkxxj5xd53w6qvqkw20u";
        let albert = Address::from_str(ALBERT).unwrap();
        let btc = Address::from_str(BTC).unwrap();
        let mut changed_keys = BTreeSet::default();
        changed_keys.insert(balance_key(&btc, &albert));
        changed_keys.insert(balance_key(
            &btc,
            &Address::Internal(InternalAddress::Masp),
        ));

        let tx = Transaction::try_from_slice(&[
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
        .expect("Test failed");
        (tx, changed_keys)
    }

    /// Test that if fetching fails before finishing,
    /// we re-establish the fetching process.
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
            .fetch::<_, _, _, TestingMaspClient>(
                &client,
                &progress,
                RetryStrategy::Times(1),
                None,
                None,
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
        let (masp_tx, changed_keys) = arbitrary_masp_tx();
        masp_tx_sender.send(None).expect("Test failed");
        masp_tx_sender
            .send(Some((
                IndexedTx {
                    height: 1.into(),
                    index: TxIndex(1),
                    is_wrapper: false,
                },
                (Default::default(), changed_keys.clone(), masp_tx.clone()),
            )))
            .expect("Test failed");
        masp_tx_sender
            .send(Some((
                IndexedTx {
                    height: 1.into(),
                    index: TxIndex(2),
                    is_wrapper: false,
                },
                (Default::default(), changed_keys, masp_tx.clone()),
            )))
            .expect("Test failed");

        // This should complete successfully
        shielded_ctx
            .fetch::<_, _, _, TestingMaspClient>(
                &client,
                &progress,
                RetryStrategy::Times(2),
                None,
                None,
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
                is_wrapper: false,
            },
            IndexedTx {
                height: 1.into(),
                index: TxIndex(2),
                is_wrapper: false,
            },
        ]);

        assert_eq!(keys, expected);
        assert_eq!(
            shielded_ctx.vk_heights[&vk].unwrap(),
            IndexedTx {
                height: 1.into(),
                index: TxIndex(2),
                is_wrapper: false,
            }
        );
        assert_eq!(shielded_ctx.note_map.len(), 2);
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
        let (masp_tx, changed_keys) = arbitrary_masp_tx();

        // first fetch no blocks
        masp_tx_sender.send(None).expect("Test failed");
        shielded_ctx
            .fetch::<_, _, _, TestingMaspClient>(
                &client,
                &progress,
                RetryStrategy::Times(1),
                None,
                None,
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
                    is_wrapper: false,
                },
                (Default::default(), changed_keys.clone(), masp_tx.clone()),
            )))
            .expect("Test failed");
        masp_tx_sender.send(None).expect("Test failed");
        shielded_ctx
            .fetch::<_, _, _, TestingMaspClient>(
                &client,
                &progress,
                RetryStrategy::Times(1),
                None,
                None,
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
            .fetch::<_, _, _, TestingMaspClient>(
                &client,
                &progress,
                RetryStrategy::Times(1),
                None,
                None,
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
            .fetch::<_, _, _, TestingMaspClient>(
                &client,
                &progress,
                RetryStrategy::Times(1),
                None,
                None,
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
                    is_wrapper: false,
                },
                (Default::default(), changed_keys.clone(), masp_tx.clone()),
            )))
            .expect("Test failed");
        masp_tx_sender
            .send(Some((
                IndexedTx {
                    height: 3.into(),
                    index: Default::default(),
                    is_wrapper: false,
                },
                (Default::default(), changed_keys.clone(), masp_tx.clone()),
            )))
            .expect("Test failed");
        // this should not produce an error since we have fetched
        // all expected blocks
        masp_tx_sender.send(None).expect("Test failed");
        shielded_ctx
            .fetch::<_, _, _, TestingMaspClient>(
                &client,
                &progress,
                RetryStrategy::Times(1),
                None,
                None,
                0,
                &[],
                &[vk],
            )
            .await
            .expect("Test failed");
        assert_eq!(progress.left_to_fetch(), 0);
    }

    /// Test that if we don't scan all fetched notes, they
    /// are persisted in a cached
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
        let (masp_tx, changed_keys) = arbitrary_masp_tx();
        masp_tx_sender
            .send(Some((
                IndexedTx {
                    height: 1.into(),
                    index: TxIndex(1),
                    is_wrapper: false,
                },
                (Default::default(), changed_keys.clone(), masp_tx.clone()),
            )))
            .expect("Test failed");
        masp_tx_sender
            .send(Some((
                IndexedTx {
                    height: 1.into(),
                    index: TxIndex(2),
                    is_wrapper: false,
                },
                (Default::default(), changed_keys.clone(), masp_tx.clone()),
            )))
            .expect("Test failed");

        shielded_ctx
            .fetch::<_, _, _, TestingMaspClient>(
                &client,
                &progress,
                RetryStrategy::Times(2),
                None,
                None,
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
            is_wrapper: false,
        }];
        assert_eq!(keys, expected);
    }

    /// Test that we cache and persist trial-decryptions
    /// when the scanning process does not complete successfully.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_decrypted_cache() {
        let temp_dir = tempdir().unwrap();
        let mut shielded_ctx =
            FsShieldedUtils::new(temp_dir.path().to_path_buf());
        let (client, masp_tx_sender) = test_client(100.into());
        let io = StdIo;
        let progress = DefaultTracker::new(&io);
        let vk = ExtendedFullViewingKey::from(
            ExtendedViewingKey::from_str(AA_VIEWING_KEY).expect("Test failed"),
        )
        .fvk
        .vk;

        // Fetch a large number of MASP notes
        let (masp_tx, changed_keys) = arbitrary_masp_tx();
        for h in 1..20 {
            masp_tx_sender
                .send(Some((
                    IndexedTx {
                        height: h.into(),
                        index: TxIndex(1),
                        is_wrapper: false,
                    },
                    (Default::default(), changed_keys.clone(), masp_tx.clone()),
                )))
                .expect("Test failed");
        }
        masp_tx_sender.send(None).expect("Test failed");

        // we expect this to fail.
        let result = shielded_ctx
            .fetch::<_, _, _, TestingMaspClient>(
                &client,
                &progress,
                RetryStrategy::Times(1),
                None,
                None,
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

        // reload the shielded context
        shielded_ctx.load_confirmed().await.expect("Test failed");

        // maliciously remove an entry from the shielded context
        // so that one of the last fetched notes will fail to scan.
        shielded_ctx.vk_heights.clear();
        shielded_ctx.tx_note_map.remove(&IndexedTx {
            height: 18.into(),
            index: TxIndex(1),
            is_wrapper: false,
        });
        shielded_ctx.save().await.expect("Test failed");

        // refetch the same MASP notes
        for h in 1..20 {
            masp_tx_sender
                .send(Some((
                    IndexedTx {
                        height: h.into(),
                        index: TxIndex(1),
                        is_wrapper: false,
                    },
                    (Default::default(), changed_keys.clone(), masp_tx.clone()),
                )))
                .expect("Test failed");
        }
        masp_tx_sender.send(None).expect("Test failed");

        // we expect this to fail.
        shielded_ctx
            .fetch::<_, _, _, TestingMaspClient>(
                &client,
                &progress,
                RetryStrategy::Times(1),
                None,
                None,
                0,
                &[],
                &[vk],
            )
            .await
            .unwrap_err();

        // because of an error in scanning, there should be elements
        // in the decrypted cache.
        shielded_ctx.load_confirmed().await.expect("Test failed");
        let result: HashMap<(IndexedTx, ViewingKey), DecryptedData> =
            shielded_ctx.decrypted_note_cache.drain().collect();
        // unfortunately we cannot easily assert what will be in this
        // cache as scanning is done in parallel, introducing non-determinism
        assert!(!result.is_empty());
    }
}
