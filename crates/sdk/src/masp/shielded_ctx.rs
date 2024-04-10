use std::cmp::Ordering;
use std::collections::{btree_map, BTreeMap, BTreeSet, HashMap, HashSet};
use std::convert::TryInto;
use std::env;
use std::str::FromStr;

use borsh::{BorshDeserialize, BorshSerialize};
use borsh_ext::BorshSerializeExt;
use itertools::Either;
use masp_primitives::asset_type::AssetType;
use masp_primitives::consensus::TestNetwork;
use masp_primitives::convert::AllowedConversion;
use masp_primitives::ff::PrimeField;
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
    ContextSyncStatus, Conversions, MaspAmount, MaspChange, ShieldedTransfer,
    TransactionDelta, TransferDelta, TransferErr, Unscanned, WalletMap,
};
use crate::masp::utils::{
    cloned_pair, extract_masp_tx, extract_payload, fetch_channel,
    get_indexed_masp_events_at_height, is_amount_required, to_viewing_key,
    DefaultLogger, ExtractShieldedActionArg, FetchQueueSender, ProgressLogger,
    ShieldedUtils, TaskManager,
};
use crate::masp::NETWORK;
#[cfg(any(test, feature = "testing"))]
use crate::masp::{testing, ENV_VAR_MASP_TEST_SEED};
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
    pub(crate) fn update_witness_map(
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

    /// Obtain a chronologically-ordered list of all accepted shielded
    /// transactions from a node.
    async fn fetch_shielded_transfers<C: Client + Sync, IO: Io>(
        mut block_sender: FetchQueueSender,
        client: &C,
        logger: &impl ProgressLogger<IO>,
        last_indexed_tx: Option<BlockHeight>,
        last_query_height: BlockHeight,
    ) -> Result<(), Error> {
        // Fetch all the transactions we do not have yet
        let first_height_to_query =
            last_indexed_tx.map_or_else(|| 1, |last| last.0);
        for height in logger.fetch(first_height_to_query..=last_query_height.0)
        {
            if block_sender.contains_height(height) {
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
                let ExtractedMaspTx {
                    fee_unshielding,
                    inner_tx,
                } = extract_masp_tx::<C>(
                    &tx,
                    ExtractShieldedActionArg::Event(&tx_event),
                    true,
                )
                .await?;
                fee_unshielding.and_then(|(changed_keys, masp_transaction)| {
                    block_sender.send((
                        IndexedTx {
                            height: height.into(),
                            index: idx,
                            is_wrapper: true,
                        },
                        (epoch, changed_keys, masp_transaction),
                    ));
                });
                inner_tx.and_then(|(changed_keys, masp_transaction)| {
                    block_sender.send((
                        IndexedTx {
                            height: height.into(),
                            index: idx,
                            is_wrapper: false,
                        },
                        (epoch, changed_keys, masp_transaction),
                    ));
                })
            }
        }
        Ok(())
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
        })?;;

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
                is_wrapper: false,
            },
            |indexed| IndexedTx {
                height: indexed.height,
                index: indexed.index + 1,
                is_wrapper: false,
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
        C: Client + Sync,
        IO: Io + Send + Sync,
        L: ProgressLogger<IO> + Sync,
    >(
        &mut self,
        client: &C,
        logger: &L,
        start_query_height: Option<BlockHeight>,
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
        let start_idx = start_query_height.or(start_idx);
        // Query for the last produced block height
        let last_block_height = query_block(client)
            .await?
            .map(|b| b.height)
            .unwrap_or_else(BlockHeight::first);
        let last_query_height = last_query_height.unwrap_or(last_block_height);
        let last_query_height =
            std::cmp::min(last_query_height, last_block_height);

        let (task_scheduler, mut task_manager) =
            TaskManager::<U>::new(self.clone());

        std::thread::scope(|s| {
            loop {
                let (fetch_send, fetch_recv) =
                    fetch_channel::new(self.unscanned.clone());
                let decryption_handle = s.spawn(|| {
                    let txs = logger.scan(fetch_recv);
                    for (indexed_tx, (epoch, tx, stx)) in txs {
                        if Some(indexed_tx) > last_witnessed_tx {
                            task_scheduler
                                .update_witness_map(indexed_tx, &stx)?;
                        }
                        let mut vk_heights = task_scheduler.get_vk_heights();
                        for (vk, h) in vk_heights
                            .iter_mut()
                            .filter(|(_vk, h)| **h < Some(indexed_tx))
                        {
                            task_scheduler.scan_tx(
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
                        task_scheduler.set_vk_heights(vk_heights);
                        task_scheduler.save(indexed_tx.height);
                    }
                    task_scheduler.complete();
                    Ok::<(), Error>(())
                });

                _ = tokio::task::block_in_place(|| {
                    tokio::runtime::Handle::current().block_on(async {
                        tokio::join!(
                            task_manager.run(),
                            Self::fetch_shielded_transfers(
                                fetch_send,
                                client,
                                logger,
                                start_idx,
                                last_query_height,
                            )
                        )
                    })
                });
                decryption_handle.join().unwrap()?;

                // if fetching failed for before completing, we restart
                // the fetch process. Otherwise, we can break the loop.
                if logger.left_to_fetch() == 0 {
                    break Ok(());
                }
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
        self.fetch(client, &DefaultLogger::new(io), None, None, 1, &[], &fvks)
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
