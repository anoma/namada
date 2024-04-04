use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::io::{Read, Write};
use std::sync::{Arc, Mutex};

use bls12_381::Bls12;
use borsh_ext::BorshSerializeExt;
use masp_primitives::asset_type::AssetType;
use masp_primitives::convert::AllowedConversion;
use masp_primitives::merkle_tree::MerklePath;
use masp_primitives::sapling::{Node, ViewingKey};
use masp_primitives::transaction::builder::{Builder, MapBuilder};
use masp_primitives::transaction::components::sapling::builder::SaplingMetadata;
use masp_primitives::transaction::components::{I128Sum, ValueSum};
use masp_primitives::transaction::{
    builder, Authorization, Authorized, Transaction, Unauthorized,
};
use masp_primitives::zip32::{ExtendedFullViewingKey, ExtendedSpendingKey};
use masp_proofs::bellman::groth16::PreparedVerifyingKey;
use namada_core::address::Address;
use namada_core::borsh::{BorshDeserialize, BorshSerialize};
use namada_core::dec::Dec;
use namada_core::storage::{BlockHeight, Epoch, IndexedTx};
use namada_core::uint::Uint;
use namada_macros::BorshDeserializer;
#[cfg(feature = "migrations")]
use namada_migrations::*;
use namada_token as token;
use thiserror::Error;

use crate::error::Error;

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

/// Represents the amount used of different conversions
pub type Conversions =
    BTreeMap<AssetType, (AllowedConversion, MerklePath<Node>, i128)>;

/// Represents the changes that were made to a list of transparent accounts
pub type TransferDelta = HashMap<Address, MaspChange>;

/// a masp amount
pub type MaspAmount = ValueSum<(Option<Epoch>, Address), token::Change>;

/// Represents the changes that were made to a list of shielded accounts
pub type TransactionDelta = HashMap<ViewingKey, I128Sum>;

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

/// Represents an authorization where the Sapling bundle is authorized and the
/// transparent bundle is unauthorized.
pub struct PartialAuthorized;

impl Authorization for PartialAuthorized {
    type SaplingAuth = <Authorized as Authorization>::SaplingAuth;
    type TransparentAuth = <Unauthorized as Authorization>::TransparentAuth;
}

/// Shielded transfer
#[derive(Clone, Debug, BorshSerialize, BorshDeserialize, BorshDeserializer)]
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
#[derive(Debug, BorshSerialize, BorshDeserialize, BorshDeserializer)]
pub struct MaspTokenRewardData {
    pub name: String,
    pub address: Address,
    pub max_reward_rate: Dec,
    pub kp_gain: Dec,
    pub kd_gain: Dec,
    pub locked_amount_target: Uint,
}

#[derive(Debug, Clone)]
struct ExtractedMaspTx {
    fee_unshielding: Option<(BTreeSet<namada_core::storage::Key>, Transaction)>,
    inner_tx: Option<(BTreeSet<namada_core::storage::Key>, Transaction)>,
}

/// MASP verifying keys
pub struct PVKs {
    /// spend verifying key
    pub spend_vk: PreparedVerifyingKey<Bls12>,
    /// convert verifying key
    pub convert_vk: PreparedVerifyingKey<Bls12>,
    /// output verifying key
    pub output_vk: PreparedVerifyingKey<Bls12>,
}

#[derive(BorshSerialize, BorshDeserialize, Debug, Copy, Clone)]
/// The possible sync states of the shielded context
pub enum ContextSyncStatus {
    /// The context contains only data that has been confirmed by the protocol
    Confirmed,
    /// The context contains that that has not yet been confirmed by the
    /// protocol and could end up being invalid
    Speculative,
}

/// a masp change
#[derive(BorshSerialize, BorshDeserialize, BorshDeserializer, Debug, Clone)]
pub struct MaspChange {
    /// the token address
    pub asset: Address,
    /// the change in the token
    pub change: token::Change,
}

/// A cache of fetched indexed transactions.
///
/// The cache is designed so that it either contains
/// all transactions from a given height, or none.
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
    pub fn extend<I>(&self, items: I)
    where
        I: IntoIterator<Item = IndexedNoteEntry>,
    {
        let mut locked = self.txs.lock().unwrap();
        locked.extend(items);
    }

    pub fn insert(&self, (k, v): IndexedNoteEntry) {
        let mut locked = self.txs.lock().unwrap();
        locked.insert(k, v);
    }

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

    pub fn pop_first(&self) -> Option<IndexedNoteEntry> {
        let mut locked = self.txs.lock().unwrap();
        locked.pop_first()
    }
}

impl IntoIterator for Unscanned {
    type IntoIter = <IndexedNoteData as IntoIterator>::IntoIter;
    type Item = IndexedNoteEntry;

    fn into_iter(self) -> Self::IntoIter {
        let txs = {
            let mut txs: IndexedNoteData = Default::default();
            let mut locked = self.txs.lock().unwrap();
            std::mem::swap(&mut txs, &mut locked);
            txs
        };
        txs.into_iter()
    }
}

/// Freeze a Builder into the format necessary for inclusion in a Tx. This is
/// the format used by hardware wallets to validate a MASP Transaction.
pub(super) struct WalletMap;

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
