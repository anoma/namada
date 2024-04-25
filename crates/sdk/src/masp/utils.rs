use core::str::FromStr;
use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::marker::PhantomData;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use borsh::{BorshDeserialize, BorshSerialize};
use masp_primitives::ff::PrimeField;
use masp_primitives::merkle_tree::{CommitmentTree, IncrementalWitness};
use masp_primitives::sapling::keys::FullViewingKey;
use masp_primitives::sapling::{Diversifier, Node, ViewingKey};
use masp_primitives::transaction::components::I128Sum;
use masp_primitives::transaction::Transaction;
use masp_primitives::zip32::{ExtendedFullViewingKey, ExtendedSpendingKey};
use masp_proofs::prover::LocalTxProver;
use namada_core::address::Address;
use namada_core::collections::HashMap;
use namada_core::storage::{BlockHeight, IndexedTx, TxIndex};
use namada_core::token::Transfer;
use namada_ibc::IbcMessage;
use namada_tx::data::{TxResult, WrapperTx};
use namada_tx::Tx;
use rand_core::{CryptoRng, RngCore};
use tokio::sync::mpsc::{Receiver, Sender};

use crate::error::{Error, QueryError};
use crate::io::Io;
use crate::masp::shielded_ctx::ShieldedContext;
use crate::masp::types::{
    ContextSyncStatus, ExtractedMaspTx, IndexedNoteEntry, PVKs, ScannedData,
    TransactionDelta, Unscanned,
};
use crate::masp::{ENV_VAR_MASP_PARAMS_DIR, VERIFIYING_KEYS};
use crate::queries::Client;
use crate::rpc::query_epoch_at_height;
use crate::{MaybeSend, MaybeSync};

/// Make sure the MASP params are present and load verifying keys into memory
pub fn preload_verifying_keys() -> &'static PVKs {
    &VERIFIYING_KEYS
}

pub(super) fn load_pvks() -> &'static PVKs {
    &VERIFIYING_KEYS
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

/// An extension of Option's cloned method for pair types
pub(super) fn cloned_pair<T: Clone, U: Clone>((a, b): (&T, &U)) -> (T, U) {
    (a.clone(), b.clone())
}

/// Extract the payload from the given Tx object
pub(super) fn extract_payload(
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
// to a valid MASP transaction. If an index is given, it filters only the
// transactions with an index equal or greater to the provided one.
pub(super) async fn get_indexed_masp_events_at_height<C: Client + Sync>(
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

pub(super) enum ExtractShieldedActionArg<'args, C: Client> {
    Event(&'args crate::tendermint::abci::Event),
    Request((&'args C, BlockHeight, Option<TxIndex>)),
}

/// Extract the relevant shielded portions of a [`Tx`], if any.
pub(super) async fn extract_masp_tx<'args, C: Client + Sync>(
    tx: &Tx,
    action_arg: ExtractShieldedActionArg<'args, C>,
    check_header: bool,
) -> Result<ExtractedMaspTx, Error> {
    // We use the changed keys instead of the Transfer object
    // because those are what the masp validity predicate works on
    let (wrapper_changed_keys, changed_keys) =
        if let ExtractShieldedActionArg::Event(tx_event) = action_arg {
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
                        "Missing required tx result in event".to_string(),
                    )
                })?;
            let result = TxResult::from_str(tx_result_str)
                .map_err(|e| Error::Other(e.to_string()))?;
            (result.wrapper_changed_keys, result.changed_keys)
        } else {
            (Default::default(), Default::default())
        };

    let tx_header = tx.header();
    // NOTE: simply looking for masp sections attached to the tx
    // is not safe. We don't validate the sections attached to a
    // transaction se we could end up with transactions carrying
    // an unnecessary masp section. We must instead look for the
    // required masp sections in the signed commitments (hashes)
    // of the transactions' headers/data sections
    let wrapper_header = tx_header
        .wrapper()
        .expect("All transactions must have a wrapper");
    let maybe_fee_unshield = if let (Some(hash), true) =
        (wrapper_header.unshield_section_hash, check_header)
    {
        let masp_transaction = tx
            .get_section(&hash)
            .ok_or_else(|| {
                Error::Other("Missing expected masp section".to_string())
            })?
            .masp_tx()
            .ok_or_else(|| {
                Error::Other("Missing masp transaction".to_string())
            })?;

        Some((wrapper_changed_keys, masp_transaction))
    } else {
        None
    };

    // Expect transaction
    let tx_data = tx
        .data()
        .ok_or_else(|| Error::Other("Missing data section".to_string()))?;
    let maybe_masp_tx = match Transfer::try_from_slice(&tx_data) {
        Ok(transfer) => Some((changed_keys, transfer)),
        Err(_) => {
            // This should be a MASP over IBC transaction, it
            // could be a ShieldedTransfer or an Envelope
            // message, need to try both
            extract_payload_from_shielded_action::<C>(&tx_data, action_arg)
                .await
                .ok()
        }
    }
    .map(|(changed_keys, transfer)| {
        if let Some(hash) = transfer.shielded {
            let masp_tx = tx
                .get_section(&hash)
                .ok_or_else(|| {
                    Error::Other(
                        "Missing masp section in transaction".to_string(),
                    )
                })?
                .masp_tx()
                .ok_or_else(|| {
                    Error::Other("Missing masp transaction".to_string())
                })?;

            Ok::<_, Error>(Some((changed_keys, masp_tx)))
        } else {
            Ok(None)
        }
    })
    .transpose()?
    .flatten();

    Ok(ExtractedMaspTx {
        fee_unshielding: maybe_fee_unshield,
        inner_tx: maybe_masp_tx,
    })
}

// Extract the changed keys and Transaction hash from a MASP over ibc message
pub(super) async fn extract_payload_from_shielded_action<
    'args,
    C: Client + Sync,
>(
    tx_data: &[u8],
    args: ExtractShieldedActionArg<'args, C>,
) -> Result<(BTreeSet<namada_core::storage::Key>, Transfer), Error> {
    let message = namada_ibc::decode_message(tx_data)
        .map_err(|e| Error::Other(e.to_string()))?;

    let result = match message {
        IbcMessage::Transfer(msg) => {
            let tx_result = get_sending_result(args)?;

            let transfer = msg.transfer.ok_or_else(|| {
                Error::Other("Missing masp tx in the ibc message".to_string())
            })?;

            (tx_result.changed_keys, transfer)
        }
        IbcMessage::NftTransfer(msg) => {
            let tx_result = get_sending_result(args)?;

            let transfer = msg.transfer.ok_or_else(|| {
                Error::Other("Missing masp tx in the ibc message".to_string())
            })?;

            (tx_result.changed_keys, transfer)
        }
        IbcMessage::RecvPacket(msg) => {
            let tx_result = get_receiving_result(args).await?;

            let transfer = msg.transfer.ok_or_else(|| {
                Error::Other("Missing masp tx in the ibc message".to_string())
            })?;

            (tx_result.changed_keys, transfer)
        }
        IbcMessage::AckPacket(msg) => {
            // Refund tokens by the ack message
            let tx_result = get_receiving_result(args).await?;

            let transfer = msg.transfer.ok_or_else(|| {
                Error::Other("Missing masp tx in the ibc message".to_string())
            })?;

            (tx_result.changed_keys, transfer)
        }
        IbcMessage::Timeout(msg) => {
            // Refund tokens by the timeout message
            let tx_result = get_receiving_result(args).await?;

            let transfer = msg.transfer.ok_or_else(|| {
                Error::Other("Missing masp tx in the ibc message".to_string())
            })?;

            (tx_result.changed_keys, transfer)
        }
        IbcMessage::Envelope(_) => {
            return Err(Error::Other(
                "Unexpected ibc message for masp".to_string(),
            ));
        }
    };

    Ok(result)
}

fn get_sending_result<C: Client + Sync>(
    args: ExtractShieldedActionArg<'_, C>,
) -> Result<TxResult, Error> {
    let tx_event = match args {
        ExtractShieldedActionArg::Event(event) => event,
        ExtractShieldedActionArg::Request(_) => {
            return Err(Error::Other(
                "Unexpected event request for ShieldedTransfer".to_string(),
            ));
        }
    };

    get_tx_result(tx_event)
}

async fn get_receiving_result<C: Client + Sync>(
    args: ExtractShieldedActionArg<'_, C>,
) -> Result<TxResult, Error> {
    let tx_event = match args {
        ExtractShieldedActionArg::Event(event) => {
            std::borrow::Cow::Borrowed(event)
        }
        ExtractShieldedActionArg::Request((client, height, index)) => {
            std::borrow::Cow::Owned(
                get_indexed_masp_events_at_height(client, height, index)
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

    get_tx_result(&tx_event)
}

fn get_tx_result(
    tx_event: &crate::tendermint::abci::Event,
) -> Result<TxResult, Error> {
    tx_event
        .attributes
        .iter()
        .find_map(|attribute| {
            if attribute.key == "inner_tx" {
                let tx_result = TxResult::from_str(&attribute.value)
                    .expect("The event value should be parsable");
                Some(tx_result)
            } else {
                None
            }
        })
        .ok_or_else(|| {
            Error::Other(
                "Couldn't find changed keys in the event for the provided \
                 transaction"
                    .to_string(),
            )
        })
}

pub struct CommitmentTreeUpdates {
    pub commitment_tree: CommitmentTree<Node>,
    pub witness_map: HashMap<usize, IncrementalWitness<Node>>,
    pub note_map_delta: BTreeMap<IndexedTx, usize>,
}

/// TODO: Used the sealed pattern?
pub trait MaspClient<'a, C: Client> {
    fn new(client: &'a C) -> Self
    where
        Self: 'a;

    #[allow(async_fn_in_trait)]
    async fn witness_map_updates<U: ShieldedUtils, IO: Io>(
        &self,
        ctx: &ShieldedContext<U>,
        io: &IO,
        last_witnessed_tx: IndexedTx,
        last_query_height: BlockHeight,
    ) -> Result<CommitmentTreeUpdates, Error>;

    #[allow(async_fn_in_trait)]
    async fn update_commitment_tree<U: ShieldedUtils, IO: Io>(
        &self,
        ctx: &mut ShieldedContext<U>,
        io: &IO,
        last_witnessed_tx: IndexedTx,
        last_query_height: BlockHeight,
    ) -> Result<(), Error> {
        let CommitmentTreeUpdates {
            commitment_tree,
            witness_map,
            mut note_map_delta,
        } = self
            .witness_map_updates(ctx, io, last_witnessed_tx, last_query_height)
            .await?;
        ctx.tree = commitment_tree;
        ctx.witness_map = witness_map;
        ctx.tx_note_map.append(&mut note_map_delta);
        Ok(())
    }

    #[allow(async_fn_in_trait)]
    async fn fetch_shielded_transfer<IO: Io>(
        &self,
        logger: &impl ProgressLogger<IO>,
        tx_sender: FetchQueueSender,
        from: u64,
        to: u64,
    ) -> Result<(), Error>;
}

/// An inefficient MASP client which simply uses a
/// client to the blockchain to query it directly.
pub struct LedgerMaspClient<'a, C: Client> {
    client: &'a C,
}

impl<'a, C: Client + Sync> MaspClient<'a, C> for LedgerMaspClient<'a, C>
where
    LedgerMaspClient<'a, C>: 'a,
{
    fn new(client: &'a C) -> Self
    where
        Self: 'a,
    {
        Self { client }
    }

    async fn witness_map_updates<U: ShieldedUtils, IO: Io>(
        &self,
        ctx: &ShieldedContext<U>,
        io: &IO,
        last_witnessed_tx: IndexedTx,
        last_query_height: BlockHeight,
    ) -> Result<CommitmentTreeUpdates, Error> {
        let (tx_sender, tx_receiver) = fetch_channel::new(Default::default());
        let logger = DefaultLogger::new(io);
        let (res, updates) = tokio::join!(
            self.fetch_shielded_transfer(
                &logger,
                tx_sender,
                last_witnessed_tx.height.0,
                last_query_height.0,
            ),
            async {
                let mut updates = CommitmentTreeUpdates {
                    commitment_tree: ctx.tree.clone(),
                    witness_map: ctx.witness_map.clone(),
                    note_map_delta: Default::default(),
                };
                for (indexed_tx, (_, _, ref shielded)) in tx_receiver {
                    let mut note_pos = updates.commitment_tree.size();
                    updates.note_map_delta.insert(indexed_tx, note_pos);
                    for so in shielded
                        .sapling_bundle()
                        .map_or(&vec![], |x| &x.shielded_outputs)
                    {
                        // Create merkle tree leaf node from note commitment
                        let node = Node::new(so.cmu.to_repr());
                        // Update each merkle tree in the witness map with the
                        // latest addition
                        for (_, witness) in updates.witness_map.iter_mut() {
                            witness.append(node).map_err(|()| {
                                Error::Other(
                                    "note commitment tree is full".to_string(),
                                )
                            })?;
                        }
                        updates.commitment_tree.append(node).map_err(|()| {
                            Error::Other(
                                "note commitment tree is full".to_string(),
                            )
                        })?;
                        // Finally, make it easier to construct merkle paths to
                        // this new note
                        let witness = IncrementalWitness::<Node>::from_tree(
                            &updates.commitment_tree,
                        );
                        updates.witness_map.insert(note_pos, witness);
                        note_pos += 1;
                    }
                }
                Ok(updates)
            }
        );
        res?;
        updates
    }

    async fn fetch_shielded_transfer<IO: Io>(
        &self,
        logger: &impl ProgressLogger<IO>,
        mut tx_sender: FetchQueueSender,
        from: u64,
        to: u64,
    ) -> Result<(), Error> {
        // Fetch all the transactions we do not have yet
        let mut fetch_iter = logger.fetch(from..=to);

        while let Some(height) = fetch_iter.peek() {
            let height = *height;
            if tx_sender.contains_height(height) {
                fetch_iter.next();
                continue;
            }
            // Get the valid masp transactions at the specified height
            let epoch = query_epoch_at_height(self.client, height.into())
                .await?
                .ok_or_else(|| {
                    Error::from(QueryError::General(
                        "Queried height is greater than the last committed \
                         block height"
                            .to_string(),
                    ))
                })?;
            let txs_results = match get_indexed_masp_events_at_height::<C>(
                self.client,
                height.into(),
                None,
            )
            .await?
            {
                Some(events) => events,
                None => {
                    fetch_iter.next();
                    continue;
                }
            };

            // Query the actual block to get the txs bytes. If we only need one
            // tx it might be slightly better to query the /tx endpoint to
            // reduce the amount of data sent over the network, but this is a
            // minimal improvement and it's even hard to tell how many times
            // we'd need a single masp tx to make this worth it
            let block = self
                .client
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
                if let Some((changed_keys, masp_transaction)) = fee_unshielding
                {
                    tx_sender.send((
                        IndexedTx {
                            height: height.into(),
                            index: idx,
                            is_wrapper: true,
                        },
                        (epoch, changed_keys, masp_transaction),
                    ));
                }
                if let Some((changed_keys, masp_transaction)) = inner_tx {
                    tx_sender.send((
                        IndexedTx {
                            height: height.into(),
                            index: idx,
                            is_wrapper: false,
                        },
                        (epoch, changed_keys, masp_transaction),
                    ));
                }
            }
            fetch_iter.next();
        }

        Ok(())
    }
}

/// A channel-like struct for "sending" newly fetched blocks
/// to the scanning algorithm.
///
/// Holds a pointer to the unscanned cache which it can append to.
/// Furthermore, has an actual channel for keeping track if
/// 1. The process in possession of the channel is still alive
/// 2. Quickly updating the latest block height scanned.
#[derive(Clone)]
pub struct FetchQueueSender {
    cache: Unscanned,
    last_fetched: flume::Sender<BlockHeight>,
}

/// A channel-like struct for "receiving" new fetched
/// blocks for the scanning algorithm.
///
/// This is implemented as an iterator for the scanning
/// algorithm. This receiver pulls from the cache until
/// it is empty. It then waits until new entries appear
/// in the cache or the sender hangs up.
#[derive(Clone)]
pub(super) struct FetchQueueReceiver {
    cache: Unscanned,
    last_fetched: flume::Receiver<BlockHeight>,
}

impl FetchQueueReceiver {
    /// Check if the sender has hung up. If so, manually calculate the latest
    /// height fetched. Otherwise, update the latest height fetched with the
    /// data provided by the sender.
    fn sender_alive(&self) -> bool {
        self.last_fetched.sender_count() > 0
    }
}

impl Iterator for FetchQueueReceiver {
    type Item = IndexedNoteEntry;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(entry) = self.cache.pop_first() {
            Some(entry)
        } else {
            while self.sender_alive() {
                if let Some(entry) = self.cache.pop_first() {
                    return Some(entry);
                }
            }
            None
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let size = self.last_fetched.len();
        (size, Some(size))
    }
}

impl FetchQueueSender {
    pub(super) fn contains_height(&self, height: u64) -> bool {
        self.cache.contains_height(height)
    }

    pub(super) fn send(&mut self, data: IndexedNoteEntry) {
        self.last_fetched.send(data.0.height).unwrap();
        self.cache.insert(data);
    }
}

/// A convenience for creating a channel for fetching blocks.
pub mod fetch_channel {

    use super::{FetchQueueReceiver, FetchQueueSender, Unscanned};
    pub(in super::super) fn new(
        cache: Unscanned,
    ) -> (FetchQueueSender, FetchQueueReceiver) {
        let (fetch_send, fetch_recv) = flume::unbounded();
        (
            FetchQueueSender {
                cache: cache.clone(),
                last_fetched: fetch_send,
            },
            FetchQueueReceiver {
                cache: cache.clone(),
                last_fetched: fetch_recv,
            },
        )
    }
}

/// The actions that the scanning process can
/// schedule to be run on the main thread.
#[allow(clippy::large_enum_variant)]
enum Action {
    /// Signal that the scanning process has ended and if it did so with
    /// an error
    Complete { with_error: bool },
    /// Send a diff of data to be applied to the ctx before
    /// persisting.
    Data(ScannedData, IndexedTx),
}

/// A process on the main thread that listens for
/// progress updates from the scanning process
/// and applies all state changes that it
/// schedules.
pub struct TaskManager<U: ShieldedUtils> {
    action: Receiver<Action>,
    pub(super) latest_idx: IndexedTx,
    ctx: Arc<futures_locks::Mutex<ShieldedContext<U>>>,
}

#[derive(Clone)]
/// A struct that allows the scanning process
/// thread to communicate errors and actions back to
/// the main process where they will be handled by
/// a [`TaskManager`].
pub(super) struct TaskScheduler<U> {
    action: Sender<Action>,
    _phantom: PhantomData<U>,
}

impl<U: ShieldedUtils + MaybeSend + MaybeSync> TaskManager<U> {
    pub(super) fn new(ctx: ShieldedContext<U>) -> (TaskScheduler<U>, Self) {
        let (action_send, action_recv) = tokio::sync::mpsc::channel(100);
        (
            TaskScheduler {
                action: action_send,
                _phantom: PhantomData,
            },
            TaskManager {
                action: action_recv,
                latest_idx: Default::default(),
                ctx: Arc::new(futures_locks::Mutex::new(ctx)),
            },
        )
    }

    /// Run all actions scheduled by the scanning thread until
    /// that process indicates it has finished.
    pub async fn run(&mut self, native_token: &Address) -> Result<(), Error> {
        while let Some(action) = self.action.recv().await {
            match action {
                // On completion, update the height to which all keys have been
                // synced and then save.
                Action::Complete { with_error } => {
                    if !with_error {
                        let mut locked = self.ctx.lock().await;
                        // update each key to be synced to the latest scanned
                        // height.
                        for (_, h) in locked.vk_heights.iter_mut() {
                            *h = Some(self.latest_idx);
                        }
                        // updated the spent notes and balances
                        locked.nullify_spent_notes(native_token)?;
                        _ = locked.save().await;
                    }
                    return Ok(());
                }
                Action::Data(scanned, idx) => {
                    // track the latest scanned height
                    self.latest_idx = idx;
                    // apply state changes from the scanning process
                    let mut locked = self.ctx.lock().await;
                    scanned.apply_to(&mut locked);
                    // possibly remove unneeded elements from the cache.
                    locked.unscanned.scanned(&idx);
                    // persist the changes
                    _ = locked.save().await;
                }
            }
        }
        Ok(())
    }
}

impl<U: ShieldedUtils> TaskScheduler<U> {
    /// Signal the [`TaskManager`] that the scanning thread has completed
    pub(super) fn complete(&self, with_error: bool) {
        _ = self.action.blocking_send(Action::Complete { with_error });
    }

    /// Schedule the [`TaskManager`] to save the latest context
    /// state changes.
    pub(super) fn save(&self, data: ScannedData, latest_idx: IndexedTx) {
        _ = self.action.blocking_send(Action::Data(data, latest_idx));
    }

    /// Calls the `scan_tx` method of the shielded context
    /// and sends any error to the [`TaskManager`]
    pub(super) fn scan_tx(
        &self,
        sync_status: ContextSyncStatus,
        indexed_tx: IndexedTx,
        tx_note_map: &BTreeMap<IndexedTx, usize>,
        shielded: &Transaction,
        vk: &ViewingKey,
    ) -> Result<(ScannedData, TransactionDelta), Error> {
        let res = ShieldedContext::<U>::scan_tx(
            sync_status,
            indexed_tx,
            tx_note_map,
            shielded,
            vk,
        );
        if res.is_err() {
            self.complete(true);
        }
        res
    }
}

/// When retrying to fetch all nodes in a
/// loop, this dictates the strategy for
/// how many attempts should be made.
pub enum RetryStrategy {
    Forever,
    Times(u64),
}

impl Iterator for RetryStrategy {
    type Item = ();

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            Self::Forever => Some(()),
            Self::Times(ref mut count) => {
                if *count == 0 {
                    None
                } else {
                    *count -= 1;
                    Some(())
                }
            }
        }
    }
}

/// An enum to indicate how to log sync progress depending on
/// whether sync is currently fetch or scanning blocks.
#[derive(Debug, Copy, Clone)]
pub enum ProgressType {
    Fetch,
    Scan,
}

pub trait PeekableIter<I> {
    fn peek(&mut self) -> Option<&I>;
    fn next(&mut self) -> Option<I>;
}

impl<I, J> PeekableIter<J> for std::iter::Peekable<I>
where
    I: Iterator<Item = J>,
{
    fn peek(&mut self) -> Option<&J> {
        self.peek()
    }

    fn next(&mut self) -> Option<J> {
        <Self as Iterator>::next(self)
    }
}

pub trait ProgressLogger<IO: Io> {
    fn io(&self) -> &IO;

    fn fetch<I>(&self, items: I) -> impl PeekableIter<u64>
    where
        I: Iterator<Item = u64>;

    fn scan<I>(
        &self,
        items: I,
    ) -> impl Iterator<Item = IndexedNoteEntry> + Send
    where
        I: Iterator<Item = IndexedNoteEntry> + Send;

    fn left_to_fetch(&self) -> usize;
}

/// The default type for logging sync progress.
#[derive(Debug, Clone)]
pub struct DefaultLogger<'io, IO: Io> {
    io: &'io IO,
    progress: Arc<Mutex<IterProgress>>,
}

impl<'io, IO: Io> DefaultLogger<'io, IO> {
    pub fn new(io: &'io IO) -> Self {
        Self {
            io,
            progress: Arc::new(Mutex::new(Default::default())),
        }
    }
}

#[derive(Default, Copy, Clone, Debug)]
struct IterProgress {
    index: usize,
    length: usize,
}

struct DefaultFetchIterator<I>
where
    I: Iterator<Item = u64>,
{
    inner: I,
    progress: Arc<Mutex<IterProgress>>,
    peeked: Option<u64>,
}

impl<I> PeekableIter<u64> for DefaultFetchIterator<I>
where
    I: Iterator<Item = u64>,
{
    fn peek(&mut self) -> Option<&u64> {
        if self.peeked.is_none() {
            self.peeked = self.inner.next();
        }
        self.peeked.as_ref()
    }

    fn next(&mut self) -> Option<u64> {
        self.peek();
        let item = self.peeked.take()?;
        let mut locked = self.progress.lock().unwrap();
        locked.index += 1;
        Some(item)
    }
}

impl<'io, IO: Io> ProgressLogger<IO> for DefaultLogger<'io, IO> {
    fn io(&self) -> &IO {
        self.io
    }

    fn fetch<I>(&self, items: I) -> impl PeekableIter<u64>
    where
        I: Iterator<Item = u64>,
    {
        {
            let mut locked = self.progress.lock().unwrap();
            locked.length = items.size_hint().0;
        }
        DefaultFetchIterator {
            inner: items,
            progress: self.progress.clone(),
            peeked: None,
        }
    }

    fn scan<I>(&self, items: I) -> impl Iterator<Item = IndexedNoteEntry> + Send
    where
        I: IntoIterator<Item = IndexedNoteEntry>,
    {
        let items: Vec<_> = items.into_iter().collect();
        items.into_iter()
    }

    fn left_to_fetch(&self) -> usize {
        let locked = self.progress.lock().unwrap();
        locked.length - locked.index
    }
}

#[cfg(test)]
mod util_tests {
    use crate::masp::utils::RetryStrategy;

    #[test]
    fn test_retry_strategy() {
        let strategy = RetryStrategy::Times(3);
        let mut counter = 0;
        for _ in strategy {
            counter += 1;
        }
        assert_eq!(counter, 3);
    }
}
