//! The shielded wallet implementation
use std::cmp::Ordering;
use std::collections::{btree_map, BTreeMap, BTreeSet};

use eyre::eyre;
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
use masp_primitives::sapling::{
    Diversifier, Node, Note, Nullifier, ViewingKey,
};
use masp_primitives::transaction::builder::Builder;
use masp_primitives::transaction::components::sapling::builder::RngBuildParams;
use masp_primitives::transaction::components::{
    I128Sum, TxOut, U64Sum, ValueSum,
};
use masp_primitives::transaction::fees::fixed::FeeRule;
use masp_primitives::transaction::{builder, Transaction};
use masp_primitives::zip32::ExtendedSpendingKey as MaspExtendedSpendingKey;
use namada_core::address::Address;
use namada_core::arith::checked;
use namada_core::borsh::{BorshDeserialize, BorshSerialize};
use namada_core::chain::BlockHeight;
use namada_core::collections::{HashMap, HashSet};
use namada_core::control_flow;
use namada_core::masp::{
    encode_asset_type, AssetData, MaspEpoch, TransferSource, TransferTarget,
};
use namada_core::task_env::TaskEnvironment;
use namada_core::time::{DateTimeUtc, DurationSecs};
use namada_core::token::{
    Amount, Change, DenominatedAmount, Denomination, MaspDigitPos,
};
use namada_io::client::Client;
use namada_io::{
    display_line, edisplay_line, Io, MaybeSend, MaybeSync, NamadaIo,
    ProgressBar,
};
use namada_tx::IndexedTx;
use namada_wallet::{DatedKeypair, DatedSpendingKey};
use rand::prelude::StdRng;
use rand_core::{OsRng, SeedableRng};

use crate::masp::utils::MaspClient;
use crate::masp::{
    cloned_pair, is_amount_required, to_viewing_key, Changes,
    ContextSyncStatus, Conversions, MaspAmount, MaspDataLog, MaspFeeData,
    MaspSourceTransferData, MaspTargetTransferData, MaspTransferData,
    MaspTxReorderedData, NoteIndex, ShieldedSyncConfig, ShieldedTransfer,
    ShieldedUtils, SpentNotesTracker, TransferErr, WalletMap, WitnessMap,
    NETWORK,
};
#[cfg(any(test, feature = "testing"))]
use crate::masp::{testing, ENV_VAR_MASP_TEST_SEED};

/// Represents the current state of the shielded pool from the perspective of
/// the chosen viewing keys.
#[derive(BorshSerialize, BorshDeserialize, Debug)]
pub struct ShieldedWallet<U: ShieldedUtils> {
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
    pub note_index: NoteIndex,
    /// The sync state of the context
    pub sync_status: ContextSyncStatus,
}

/// Default implementation to ease construction of TxContexts. Derive cannot be
/// used here due to CommitmentTree not implementing Default.
impl<U: ShieldedUtils + Default> Default for ShieldedWallet<U> {
    fn default() -> ShieldedWallet<U> {
        ShieldedWallet::<U> {
            utils: U::default(),
            vk_heights: BTreeMap::new(),
            note_index: BTreeMap::default(),
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

impl<U: ShieldedUtils + MaybeSend + MaybeSync> ShieldedWallet<U> {
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
    pub(crate) fn update_witness_map(
        &mut self,
        indexed_tx: IndexedTx,
        shielded: &Transaction,
    ) -> Result<(), eyre::Error> {
        let mut note_pos = self.tree.size();
        self.note_index.insert(indexed_tx, note_pos);

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
                    eyre!("note commitment tree is full".to_string())
                })?;
            }
            self.tree.append(node).map_err(|()| {
                eyre!("note commitment tree is full".to_string())
            })?;
            // Finally, make it easier to construct merkle paths to this new
            // note
            let witness = IncrementalWitness::<Node>::from_tree(&self.tree);
            self.witness_map.insert(note_pos, witness);
            note_pos = checked!(note_pos + 1).unwrap();
        }
        Ok(())
    }

    /// Sync the current state of the multi-asset shielded pool in a
    /// ShieldedContext with the state on-chain.
    pub async fn sync<M, T, I>(
        &mut self,
        env: impl TaskEnvironment,
        config: ShieldedSyncConfig<M, T, I>,
        last_query_height: Option<BlockHeight>,
        sks: &[DatedSpendingKey],
        fvks: &[DatedKeypair<ViewingKey>],
    ) -> Result<(), eyre::Error>
    where
        M: MaspClient + Send + Sync + Unpin + 'static,
        T: ProgressBar,
        I: control_flow::ShutdownSignal,
    {
        env.run(|spawner| async move {
            let dispatcher = config.dispatcher(spawner, &self.utils).await;

            if let Some(updated_ctx) =
                dispatcher.run(None, last_query_height, sks, fvks).await?
            {
                *self = updated_ctx;
            }

            Ok(())
        })
        .await
    }

    pub(crate) fn min_height_to_sync_from(
        &self,
    ) -> Result<BlockHeight, eyre::Error> {
        let Some(maybe_least_synced_vk_height) =
            self.vk_heights.values().min().cloned()
        else {
            return Err(eyre!(
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
    ) -> Result<(), eyre::Error> {
        // Add this note to list of notes decrypted by this
        // viewing key
        self.pos_map.entry(*vk).or_default().insert(note_pos);
        // Compute the nullifier now to quickly recognize when
        // spent
        let nf = note.nf(
            &vk.nk,
            note_pos
                .try_into()
                .map_err(|_| eyre!("Can not get nullifier".to_string()))?,
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
    pub fn save_shielded_spends(&mut self, transaction: &Transaction) {
        for ss in transaction
            .sapling_bundle()
            .map_or(&vec![], |x| &x.shielded_spends)
        {
            // If the shielded spend's nullifier is in our map, then target
            // note is rendered unusable
            if let Some(note_pos) = self.nf_map.get(&ss.nullifier) {
                self.spents.insert(*note_pos);
            }
        }
    }

    /// Compute the total unspent notes associated with the viewing key in the
    /// context. If the key is not in the context, then we do not know the
    /// balance and hence we return None.
    pub async fn compute_shielded_balance(
        &mut self,
        vk: &ViewingKey,
    ) -> Result<Option<I128Sum>, eyre::Error> {
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
                let note = self
                    .note_map
                    .get(note_idx)
                    .ok_or_else(|| eyre!("Unable to get note {note_idx}"))?;
                // Finally add value to multi-asset accumulator
                val_acc += I128Sum::from_nonnegative(
                    note.asset_type,
                    i128::from(note.value),
                )
                .map_err(|()| {
                    eyre!("found note with invalid value or asset type")
                })?
            }
        }
        Ok(Some(val_acc))
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
    ) -> Result<(), eyre::Error> {
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

    /// Updates the internal state with the data of the newly generated
    /// transaction. More specifically invalidate the spent notes, but do not
    /// cache the newly produced output descriptions and therefore the merkle
    /// tree
    async fn pre_cache_transaction(
        &mut self,
        masp_tx: &Transaction,
    ) -> Result<(), eyre::Error> {
        self.save_shielded_spends(masp_tx);

        // Save the speculative state for future usage
        self.sync_status = ContextSyncStatus::Speculative;
        self.save().await.map_err(|e| eyre!(e.to_string()))?;

        Ok(())
    }
}

/// A trait that allows downstream types specify how a shielded wallet
/// should interact / query a node.
pub trait ShieldedQueries<U: ShieldedUtils + MaybeSend + MaybeSync>:
    std::ops::Deref<Target = ShieldedWallet<U>> + std::ops::DerefMut
{
    /// Get the address of the native token
    #[allow(async_fn_in_trait)]
    async fn query_native_token<C: Client + Sync>(
        client: &C,
    ) -> Result<Address, eyre::Error>;

    /// Query the denomination of a token type
    #[allow(async_fn_in_trait)]
    async fn query_denom<C: Client + Sync>(
        client: &C,
        token: &Address,
    ) -> Option<Denomination>;

    /// Query for converting assets across epochs
    #[allow(async_fn_in_trait)]
    async fn query_conversion<C: Client + Sync>(
        client: &C,
        asset_type: AssetType,
    ) -> Option<(
        Address,
        Denomination,
        MaspDigitPos,
        MaspEpoch,
        I128Sum,
        MerklePath<Node>,
    )>;

    /// Get the last block height
    #[allow(async_fn_in_trait)]
    async fn query_block<C: Client + Sync>(
        client: &C,
    ) -> Result<Option<u64>, eyre::Error>;

    /// Get the upper limit on the time to make a new block
    #[allow(async_fn_in_trait)]
    async fn query_max_block_time_estimate<C: Client + Sync>(
        client: &C,
    ) -> Result<DurationSecs, eyre::Error>;

    /// Query the MASP epoch
    #[allow(async_fn_in_trait)]
    async fn query_masp_epoch<C: Client + Sync>(
        client: &C,
    ) -> Result<MaspEpoch, eyre::Error>;
}

///  The methods of the shielded wallet that depend on the [`ShieldedQueries`]
/// trait. These cannot be overridden downstream.
pub trait ShieldedApi<U: ShieldedUtils + MaybeSend + MaybeSync>:
    ShieldedQueries<U>
{
    /// Use the addresses already stored in the wallet to precompute as many
    /// asset types as possible.
    #[allow(async_fn_in_trait)]
    async fn precompute_asset_types<C: Client + Sync>(
        &mut self,
        client: &C,
        tokens: Vec<&Address>,
    ) -> Result<(), eyre::Error> {
        // To facilitate lookups of human-readable token names
        for token in tokens {
            let Some(denom) = Self::query_denom(client, token).await else {
                return Err(eyre!("denomination for token {token}"));
            };
            for position in MaspDigitPos::iter() {
                let asset_type =
                    encode_asset_type(token.clone(), denom, position, None)
                        .map_err(|_| eyre!("unable to create asset type",))?;
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
    #[allow(async_fn_in_trait)]
    async fn decode_asset_type<C: Client + Sync>(
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
        ) = Self::query_conversion(client, asset_type).await?;
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
    #[allow(async_fn_in_trait)]
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
                Self::query_conversion(client, asset_type).await
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

    /// Convert the given amount into the latest asset types whilst making a
    /// note of the conversions that were used. Note that this function does
    /// not assume that allowed conversions from the ledger are expressed in
    /// terms of the latest asset types.
    #[allow(async_fn_in_trait)]
    async fn compute_exchanged_amount(
        &mut self,
        client: &(impl Client + Sync),
        io: &impl Io,
        mut input: I128Sum,
        target_epoch: MaspEpoch,
        mut conversions: Conversions,
    ) -> Result<(I128Sum, I128Sum, Conversions), eyre::Error> {
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
                        .map_err(|_| eyre!("unable to create asset type",))
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

    /// Compute the total unspent notes associated with the viewing key in the
    /// context and express that value in terms of the currently timestamped
    /// asset types. If the key is not in the context, then we do not know the
    /// balance and hence we return None.
    #[allow(async_fn_in_trait)]
    async fn compute_exchanged_balance(
        &mut self,
        client: &(impl Client + Sync),
        io: &impl Io,
        vk: &ViewingKey,
        target_epoch: MaspEpoch,
    ) -> Result<Option<I128Sum>, eyre::Error> {
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

    /// Collect enough unspent notes in this context to exceed the given amount
    /// of the specified asset type. Return the total value accumulated plus
    /// notes and the corresponding diversifiers/merkle paths that were used to
    /// achieve the total value. Updates the changes map.
    #[allow(clippy::too_many_arguments)]
    #[allow(async_fn_in_trait)]
    async fn collect_unspent_notes(
        &mut self,
        context: &impl NamadaIo,
        spent_notes: &mut SpentNotesTracker,
        sk: namada_core::masp::ExtendedSpendingKey,
        target: I128Sum,
        target_epoch: MaspEpoch,
        changes: &mut Changes,
    ) -> Result<
        (
            I128Sum,
            Vec<(Diversifier, Note, MerklePath<Node>)>,
            Conversions,
        ),
        eyre::Error,
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
                let note = *self
                    .note_map
                    .get(note_idx)
                    .ok_or_else(|| eyre!("Unable to get note {note_idx}"))?;

                // The amount contributed by this note before conversion
                let pre_contr =
                    I128Sum::from_pair(note.asset_type, i128::from(note.value));
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
                if let Some(change) = is_amount_required(
                    normed_val_acc.clone(),
                    target.clone(),
                    normed_contr.clone(),
                    contr.clone(),
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
                        .ok_or_else(|| eyre!("Unable to get note {note_idx}"))?
                        .path()
                        .ok_or_else(|| {
                            eyre!("Unable to get path: {}", line!())
                        })?;
                    let diversifier =
                        self.div_map.get(note_idx).ok_or_else(|| {
                            eyre!("Unable to get note {note_idx}")
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
    #[allow(async_fn_in_trait)]
    async fn decode_combine_sum_to_epoch<C: Client + Sync>(
        &mut self,
        client: &C,
        amt: I128Sum,
        target_epoch: MaspEpoch,
    ) -> (ValueSum<Address, Change>, I128Sum) {
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
                    let decoded_change = Change::from_masp_denominated(
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
    #[allow(async_fn_in_trait)]
    async fn decode_combine_sum<C: Client + Sync>(
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
                let decoded_change =
                    Change::from_masp_denominated(*val, decoded.position)
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
    #[allow(async_fn_in_trait)]
    async fn decode_sum<C: Client + Sync>(
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
    /// shielded components are produced. Otherwise, a transaction containing
    /// nullifiers and/or note commitments are produced. Dummy transparent
    /// UTXOs are sometimes used to make transactions balanced, but it is
    /// understood that transparent account changes are effected only by the
    /// amounts and signatures specified by the containing Transfer object.
    #[allow(async_fn_in_trait)]
    async fn gen_shielded_transfer(
        &mut self,
        context: &impl NamadaIo,
        data: Vec<MaspTransferData>,
        fee_data: Option<MaspFeeData>,
        expiration: Option<DateTimeUtc>,
        update_ctx: bool,
    ) -> Result<Option<ShieldedTransfer>, TransferErr> {
        // Determine epoch in which to submit potential shielded transaction
        let epoch = Self::query_masp_epoch(context.client())
            .await
            .map_err(|e| TransferErr::General(e.to_string()))?;
        // Try to get a seed from env var, if any.
        #[allow(unused_mut)]
        let mut rng = StdRng::from_rng(OsRng).unwrap();
        #[cfg(feature = "testing")]
        let mut rng = if let Ok(seed) = std::env::var(ENV_VAR_MASP_TEST_SEED)
            .map_err(|e| TransferErr::General(e.to_string()))
            .and_then(|seed| {
                let exp_str =
                    format!("Env var {ENV_VAR_MASP_TEST_SEED} must be a u64.");
                let parsed_seed: u64 =
                    seed.parse().map_err(|_| TransferErr::General(exp_str))?;
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
        // we set for the transaction (since we compute two different
        // DateTimeUtc::now()). This should be small enough to not cause
        // any issue, in case refactor the build process to compute a single
        // expiration at the beginning and use it both here and for the
        // transaction
        let expiration_height: u32 = match expiration {
            Some(expiration) => {
                // Try to match a DateTime expiration with a plausible
                // corresponding block height
                let last_block_height = Self::query_block(context.client())
                    .await
                    .map_err(|e| TransferErr::General(e.to_string()))?
                    .unwrap_or(1);
                let max_block_time =
                    Self::query_max_block_time_estimate(context.client())
                        .await
                        .map_err(|e| TransferErr::General(e.to_string()))?;

                #[allow(clippy::disallowed_methods)]
                let current_time = DateTimeUtc::now();
                let delta_time =
                    expiration.0.signed_duration_since(current_time.0);

                let delta_blocks = u32::try_from(
                    delta_time.num_seconds()
                        / i64::try_from(max_block_time.0).unwrap(),
                )
                .map_err(|e| TransferErr::General(e.to_string()))?;
                u32::try_from(last_block_height)
                    .map_err(|e| TransferErr::General(e.to_string()))?
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

        let mut notes_tracker = SpentNotesTracker::new();
        {
            // Load the current shielded context given
            // the spending key we possess
            let _ = self.load().await;
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
            self.add_inputs(
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
            self.add_outputs(
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
            self.add_fees(
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
        let prover = self.utils.local_tx_prover();
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
            self.pre_cache_transaction(&masp_tx)
                .await
                .map_err(|e| TransferErr::General(e.to_string()))?;
        }

        Ok(Some(ShieldedTransfer {
            builder: builder_clone,
            masp_tx,
            metadata,
            epoch,
        }))
    }

    /// Group all the information for every source/token and target/token
    /// couple, and extract the denominations for all the tokens involved
    /// (expect the one involved in the fees if needed). This step is
    /// required so that we can collect the amount required for every couple
    /// and pass it to the appropriate function so that notes can be
    /// collected based on the correct amount.
    #[allow(async_fn_in_trait)]
    async fn reorder_data_for_masp_transfer(
        context: &impl NamadaIo,
        data: Vec<MaspTransferData>,
    ) -> Result<Option<MaspTxReorderedData>, TransferErr> {
        let mut source_data =
            HashMap::<MaspSourceTransferData, DenominatedAmount>::new();
        let mut target_data =
            HashMap::<MaspTargetTransferData, DenominatedAmount>::new();
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
                if let Some(denom) =
                    Self::query_denom(context.client(), &token).await
                {
                    denoms.insert(token.clone(), denom);
                } else {
                    return Err(TransferErr::General(format!(
                        "denomination for token {token}"
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
                        .map_err(|e| TransferErr::General(e.to_string()))?;
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
                        .map_err(|e| TransferErr::General(e.to_string()))?;
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

    /// Add the necessary transaction inputs to the builder.
    #[allow(async_fn_in_trait)]
    #[allow(clippy::too_many_arguments)]
    async fn add_inputs(
        &mut self,
        context: &impl NamadaIo,
        builder: &mut Builder<Network>,
        source: &TransferSource,
        token: &Address,
        amount: &DenominatedAmount,
        epoch: MaspEpoch,
        denoms: &HashMap<Address, Denomination>,
        notes_tracker: &mut SpentNotesTracker,
        changes: &mut Changes,
    ) -> Result<Option<I128Sum>, TransferErr> {
        // We want to fund our transaction solely from supplied spending key
        let spending_key = source.spending_key();

        // Now we build up the transaction within this object

        // Convert transaction amount into MASP types
        // Ok to unwrap because we've already seen the token before, the
        // denomination must be there
        let denom = denoms.get(token).unwrap();
        let (asset_types, masp_amount) = {
            // Do the actual conversion to an asset type
            let amount = self
                .convert_namada_amount_to_masp(
                    context.client(),
                    epoch,
                    token,
                    denom.to_owned(),
                    amount.amount(),
                )
                .await
                .map_err(|e| TransferErr::General(e.to_string()))?;
            // Make sure to save any decodings of the asset types used so
            // that balance queries involving them are
            // successful
            let _ = self.save().await;
            amount
        };

        // If there are shielded inputs
        let added_amt = if let Some(sk) = spending_key {
            // Locate unspent notes that can help us meet the transaction
            // amount
            let (added_amount, unspent_notes, used_convs) = self
                .collect_unspent_notes(
                    context,
                    notes_tracker,
                    sk,
                    I128Sum::from_sum(masp_amount),
                    epoch,
                    changes,
                )
                .await
                .map_err(|e| TransferErr::General(e.to_string()))?;
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
                    TransferErr::General(
                        "source address should be transparent".into(),
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

    /// Add the necessary transaction outputs to the builder
    #[allow(clippy::too_many_arguments)]
    #[allow(async_fn_in_trait)]
    async fn add_outputs(
        &mut self,
        context: &impl NamadaIo,
        builder: &mut Builder<Network>,
        source: TransferSource,
        target: &TransferTarget,
        token: Address,
        amount: DenominatedAmount,
        epoch: MaspEpoch,
        denoms: &HashMap<Address, Denomination>,
    ) -> Result<(), TransferErr> {
        // Anotate the asset type in the value balance with its decoding in
        // order to facilitate cross-epoch computations
        let value_balance = self
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
                let contr = std::cmp::min(u128::from(*rem_amount), val) as u64;
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
                    return Result::Err(TransferErr::General(
                        "transaction target must be a payment address or \
                         Namada address or IBC address"
                            .to_string(),
                    ));
                }
                // Lower what is required of the remaining contribution
                *rem_amount -= contr;
            }
        }

        // Nothing must remain to be included in output
        if rem_amount != [0; 4] {
            let (asset_types, _) = {
                // Do the actual conversion to an asset type
                let amount = self
                    .convert_namada_amount_to_masp(
                        context.client(),
                        epoch,
                        &token,
                        denom.to_owned(),
                        amount.amount(),
                    )
                    .await
                    .map_err(|e| TransferErr::General(e.to_string()))?;
                // Make sure to save any decodings of the asset types used so
                // that balance queries involving them are
                // successful
                let _ = self.save().await;
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

    /// Add the necessary note to include a masp fee payment in the transaction.
    /// Funds are gathered in the following order:
    ///
    /// 1. From the residual values of the already included spend notes (i.e.
    ///    changes)
    /// 2. From new spend notes of the transaction's sources
    /// 3. From new spend notes of the optional gas spending keys
    #[allow(clippy::too_many_arguments)]
    #[allow(async_fn_in_trait)]
    async fn add_fees(
        &mut self,
        context: &impl NamadaIo,
        builder: &mut Builder<Network>,
        source_data: &HashMap<MaspSourceTransferData, DenominatedAmount>,
        sources: Vec<namada_core::masp::ExtendedSpendingKey>,
        target: &Address,
        token: &Address,
        amount: &DenominatedAmount,
        epoch: MaspEpoch,
        denoms: &mut HashMap<Address, Denomination>,
        notes_tracker: &mut SpentNotesTracker,
        changes: &mut Changes,
    ) -> Result<(), TransferErr> {
        if denoms.get(token).is_none() {
            if let Some(denom) =
                Self::query_denom(context.client(), token).await
            {
                denoms.insert(token.to_owned(), denom);
            } else {
                return Err(TransferErr::General(format!(
                    "denomination for token {token}"
                )));
            };
        }
        let raw_amount = amount.amount().raw_amount().0;
        let (asset_types, _) = {
            // Do the actual conversion to an asset type
            let (asset_types, amount) = self
                .convert_namada_amount_to_masp(
                    context.client(),
                    epoch,
                    token,
                    // Safe to unwrap
                    denoms.get(token).unwrap().to_owned(),
                    amount.amount(),
                )
                .await
                .map_err(|e| TransferErr::General(e.to_string()))?;
            // Make sure to save any decodings of the asset types used so
            // that balance queries involving them are
            // successful
            let _ = self.save().await;
            (asset_types, amount)
        };

        let mut fees = I128Sum::zero();
        // Convert the shortfall into a I128Sum
        for (asset_type, val) in asset_types.iter().zip(raw_amount) {
            fees += I128Sum::from_nonnegative(*asset_type, val.into())
                .map_err(|()| {
                    TransferErr::General(
                        "Fee amount is expected expected to be non-negative"
                            .to_string(),
                    )
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
                        TransferErr::General(
                            "Fee amount is expected to be non-negative"
                                .to_string(),
                        )
                    })?;
                    let denominated_output_amt = self
                        .convert_masp_amount_to_namada(
                            context.client(),
                            // Safe to unwrap
                            denoms.get(token).unwrap().to_owned(),
                            output_amt.clone(),
                        )
                        .await
                        .map_err(|e| TransferErr::General(e.to_string()))?;

                    self.add_outputs(
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
                    TransferErr::General(
                        "Fee amount is expected expected to be non-negative"
                            .to_string(),
                    )
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
                        TransferErr::General(
                            "Fee amount is expected expected to be \
                             non-negative"
                                .to_string(),
                        )
                    })?;
                    let denominated_fee = self
                        .convert_masp_amount_to_namada(
                            context.client(),
                            // Safe to unwrap
                            denoms.get(token).unwrap().to_owned(),
                            input_amt.clone(),
                        )
                        .await
                        .map_err(|e| TransferErr::General(e.to_string()))?;

                    let Some(found_amt) = self
                        .add_inputs(
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
                        .await
                        .map_err(|e| TransferErr::General(e.to_string()))?
                    else {
                        continue;
                    };
                    // Pick the minimum between the due fee and the amount found
                    let output_amt = match found_amt.partial_cmp(&input_amt) {
                        None | Some(Ordering::Less) => found_amt,
                        _ => input_amt.clone(),
                    };
                    let denom_amt = self
                        .convert_masp_amount_to_namada(
                            context.client(),
                            // Safe to unwrap
                            denoms.get(token).unwrap().to_owned(),
                            output_amt.clone(),
                        )
                        .await
                        .map_err(|e| TransferErr::General(e.to_string()))?;

                    self.add_outputs(
                        context,
                        builder,
                        fee_source.clone(),
                        &TransferTarget::Address(target.clone()),
                        token.clone(),
                        denom_amt,
                        epoch,
                        denoms,
                    )
                    .await
                    .map_err(|e| TransferErr::General(e.to_string()))?;

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

    /// Consumes the changes and adds them back to the original sources to
    /// balance the transaction. This function has to be called after
    /// `add_fees` because we might have some change coming from there too
    #[allow(clippy::result_large_err)]
    #[allow(async_fn_in_trait)]
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

    /// Get the asset type with the given epoch, token, and denomination. If it
    /// does not exist in the protocol, then remove the timestamp. Make sure to
    /// store the derived AssetType so that future decoding is possible.
    #[allow(async_fn_in_trait)]
    async fn get_asset_type<C: Client + Sync>(
        &mut self,
        client: &C,
        decoded: &mut AssetData,
    ) -> Result<AssetType, eyre::Error> {
        let mut asset_type = decoded
            .encode()
            .map_err(|_| eyre!("unable to create asset type"))?;
        if self.decode_asset_type(client, asset_type).await.is_none() {
            // If we fail to decode the epoched asset type, then remove the
            // epoch
            decoded.undate();
            asset_type = decoded
                .encode()
                .map_err(|_| eyre!("unable to create asset type"))?;
            self.asset_types.insert(asset_type, decoded.clone());
        }
        Ok(asset_type)
    }

    /// Convert Namada amount and token type to MASP equivalents
    #[allow(async_fn_in_trait)]
    async fn convert_namada_amount_to_masp<C: Client + Sync>(
        &mut self,
        client: &C,
        epoch: MaspEpoch,
        token: &Address,
        denom: Denomination,
        val: Amount,
    ) -> Result<([AssetType; 4], U64Sum), eyre::Error> {
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
                    .map_err(|_| eyre!("invalid value for amount"))?;
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
    #[allow(async_fn_in_trait)]
    async fn convert_masp_amount_to_namada<C: Client + Sync>(
        &mut self,
        client: &C,
        denom: Denomination,
        amt: I128Sum,
    ) -> Result<DenominatedAmount, eyre::Error> {
        let mut amount = Amount::zero();
        let value_sum = self.decode_sum(client, amt).await;

        for ((_, decoded), val) in value_sum.components() {
            let positioned_amt =
                Amount::from_masp_denominated_i128(*val, decoded.position)
                    .unwrap_or_default();
            amount = checked!(amount + positioned_amt)?;
        }

        Ok(DenominatedAmount::new(amount, denom))
    }
}

impl<U: ShieldedUtils + MaybeSend + MaybeSync, T: ShieldedQueries<U>>
    ShieldedApi<U> for T
{
}
