//! MASP verification wrappers.

use std::collections::hash_map::Entry;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::env;
use std::fmt::Debug;
#[cfg(feature = "masp-tx-gen")]
use std::ops::Deref;
use std::path::PathBuf;

use async_trait::async_trait;
// use async_std::io::prelude::WriteExt;
// use async_std::io::{self};
use borsh::{BorshDeserialize, BorshSerialize};
use itertools::Either;
use masp_primitives::asset_type::AssetType;
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
#[cfg(feature = "masp-tx-gen")]
use masp_primitives::transaction::builder::{self, *};
use masp_primitives::transaction::components::sapling::builder::SaplingMetadata;
use masp_primitives::transaction::components::transparent::builder::TransparentBuilder;
use masp_primitives::transaction::components::{
    Amount, ConvertDescription, OutputDescription, SpendDescription, TxOut,
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
use masp_proofs::sapling::SaplingVerificationContext;
use namada_core::types::transaction::AffineCurve;
#[cfg(feature = "masp-tx-gen")]
use rand_core::{CryptoRng, OsRng, RngCore};
use ripemd::Digest as RipemdDigest;
#[cfg(feature = "masp-tx-gen")]
use sha2::Digest;

use crate::ledger::queries::Client;
use crate::ledger::rpc::query_storage_value;
use crate::ledger::{args, rpc};
use crate::proto::Tx;
use crate::tendermint_rpc::query::Query;
use crate::tendermint_rpc::Order;
use crate::types::address::{masp, Address};
use crate::types::masp::{BalanceOwner, ExtendedViewingKey, PaymentAddress};
use crate::types::storage::{BlockHeight, Epoch, Key, KeySeg, TxIndex};
use crate::types::token;
use crate::types::token::{
    Transfer, HEAD_TX_KEY, PIN_KEY_PREFIX, TX_KEY_PREFIX,
};
use crate::types::transaction::{EllipticCurve, PairingEngine, WrapperTx};

/// Env var to point to a dir with MASP parameters. When not specified,
/// the default OS specific path is used.
pub const ENV_VAR_MASP_PARAMS_DIR: &str = "NAMADA_MASP_PARAMS_DIR";

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

fn load_pvks() -> (
    PreparedVerifyingKey<Bls12>,
    PreparedVerifyingKey<Bls12>,
    PreparedVerifyingKey<Bls12>,
) {
    let params_dir = get_params_dir();
    let [spend_path, convert_path, output_path] =
        [SPEND_NAME, CONVERT_NAME, OUTPUT_NAME].map(|p| params_dir.join(p));

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
    (params.spend_vk, params.convert_vk, params.output_vk)
}

/// check_spend wrapper
pub fn check_spend(
    spend: &SpendDescription<<Authorized as Authorization>::SaplingAuth>,
    sighash: &[u8; 32],
    ctx: &mut SaplingVerificationContext,
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
    ctx: &mut SaplingVerificationContext,
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
    ctx: &mut SaplingVerificationContext,
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

    let (spend_pvk, convert_pvk, output_pvk) = load_pvks();

    let mut ctx = SaplingVerificationContext::new(true);
    let spends_valid = sapling_bundle.shielded_spends.iter().all(|spend| {
        check_spend(spend, sighash.as_ref(), &mut ctx, &spend_pvk)
    });
    let converts_valid = sapling_bundle
        .shielded_converts
        .iter()
        .all(|convert| check_convert(convert, &mut ctx, &convert_pvk));
    let outputs_valid = sapling_bundle
        .shielded_outputs
        .iter()
        .all(|output| check_output(output, &mut ctx, &output_pvk));

    if !(spends_valid && outputs_valid && converts_valid) {
        return false;
    }

    tracing::info!("passed spend/output verification");

    let assets_and_values: Amount = sapling_bundle.value_balance.clone();

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
#[async_trait(? Send)]
pub trait ShieldedUtils:
    Sized + BorshDeserialize + BorshSerialize + Default + Clone
{
    /// The type of the Tendermint client to make queries with
    type C: crate::ledger::queries::Client + std::marker::Sync;

    /// Get a MASP transaction prover
    fn local_tx_prover(&self) -> LocalTxProver;

    /// Load up the currently saved ShieldedContext
    async fn load(self) -> std::io::Result<ShieldedContext<Self>>;

    /// Sace the given ShieldedContext for future loads
    async fn save(&self, ctx: &ShieldedContext<Self>) -> std::io::Result<()>;
}

/// Make a ViewingKey that can view notes encrypted by given ExtendedSpendingKey
pub fn to_viewing_key(esk: &ExtendedSpendingKey) -> FullViewingKey {
    ExtendedFullViewingKey::from(esk).fvk
}

/// Generate a valid diversifier, i.e. one that has a diversified base. Return
/// also this diversified base.
#[cfg(feature = "masp-tx-gen")]
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
pub struct ShieldedContext<U: ShieldedUtils> {
    /// Location where this shielded context is saved
    #[borsh_skip]
    pub utils: U,
    /// The last transaction index to be processed in this context
    pub last_txidx: u64,
    /// The commitment tree produced by scanning all transactions up to tx_pos
    pub tree: CommitmentTree<Node>,
    /// Maps viewing keys to applicable note positions
    pub pos_map: HashMap<ViewingKey, HashSet<usize>>,
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
    pub delta_map: BTreeMap<
        (BlockHeight, TxIndex),
        (Epoch, TransferDelta, TransactionDelta),
    >,
    /// The set of note positions that have been spent
    pub spents: HashSet<usize>,
    /// Maps asset types to their decodings
    pub asset_types: HashMap<AssetType, (Address, Epoch)>,
    /// Maps note positions to their corresponding viewing keys
    pub vk_map: HashMap<usize, ViewingKey>,
}

/// Default implementation to ease construction of TxContexts. Derive cannot be
/// used here due to CommitmentTree not implementing Default.
impl<U: ShieldedUtils + Default> Default for ShieldedContext<U> {
    fn default() -> ShieldedContext<U> {
        ShieldedContext::<U> {
            utils: U::default(),
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

impl<U: ShieldedUtils> ShieldedContext<U> {
    /// Try to load the last saved shielded context from the given context
    /// directory. If this fails, then leave the current context unchanged.
    pub async fn load(&mut self) -> std::io::Result<()> {
        let new_ctx = self.utils.clone().load().await?;
        *self = new_ctx;
        Ok(())
    }

    /// Save this shielded context into its associated context directory
    pub async fn save(&self) -> std::io::Result<()> {
        self.utils.save(self).await
    }

    /// Merge data from the given shielded context into the current shielded
    /// context. It must be the case that the two shielded contexts share the
    /// same last transaction ID and share identical commitment trees.
    pub fn merge(&mut self, new_ctx: ShieldedContext<U>) {
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
        client: &U::C,
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
            txs = Self::fetch_shielded_transfers(client, 0).await;
            tx_iter = txs.iter();
            // Do this by constructing a shielding context only for unknown keys
            let mut tx_ctx = Self {
                utils: self.utils.clone(),
                ..Default::default()
            };
            for vk in unknown_keys {
                tx_ctx.pos_map.entry(vk).or_insert_with(HashSet::new);
            }
            // Update this unknown shielded context until it is level with self
            while tx_ctx.last_txidx != self.last_txidx {
                if let Some(((height, idx), (epoch, tx, stx))) = tx_iter.next()
                {
                    tx_ctx.scan_tx(*height, *idx, *epoch, tx, stx);
                } else {
                    break;
                }
            }
            // Merge the context data originating from the unknown keys into the
            // current context
            self.merge(tx_ctx);
        } else {
            // Load only transactions accepted from last_txid until this point
            txs = Self::fetch_shielded_transfers(client, self.last_txidx).await;
            tx_iter = txs.iter();
        }
        // Now that we possess the unspent notes corresponding to both old and
        // new keys up until tx_pos, proceed to scan the new transactions.
        for ((height, idx), (epoch, tx, stx)) in &mut tx_iter {
            self.scan_tx(*height, *idx, *epoch, tx, stx);
        }
    }

    /// Obtain a chronologically-ordered list of all accepted shielded
    /// transactions from the ledger. The ledger conceptually stores
    /// transactions as a vector. More concretely, the HEAD_TX_KEY location
    /// stores the index of the last accepted transaction and each transaction
    /// is stored at a key derived from its index.
    pub async fn fetch_shielded_transfers(
        client: &U::C,
        last_txidx: u64,
    ) -> BTreeMap<(BlockHeight, TxIndex), (Epoch, Transfer, Transaction)> {
        // The address of the MASP account
        let masp_addr = masp();
        // Construct the key where last transaction pointer is stored
        let head_tx_key = Key::from(masp_addr.to_db_key())
            .push(&HEAD_TX_KEY.to_owned())
            .expect("Cannot obtain a storage key");
        // Query for the index of the last accepted transaction
        let head_txidx = query_storage_value::<U::C, u64>(client, &head_tx_key)
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
            let (tx_epoch, tx_height, tx_index, current_tx, current_stx) =
                query_storage_value::<
                    U::C,
                    (Epoch, BlockHeight, TxIndex, Transfer, Transaction),
                >(client, &current_tx_key)
                .await
                .unwrap();
            // Collect the current transaction
            shielded_txs.insert(
                (tx_height, tx_index),
                (tx_epoch, current_tx, current_stx),
            );
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
    /// https://zips.z.cash/protocol/protocol.pdf#scan
    pub fn scan_tx(
        &mut self,
        height: BlockHeight,
        index: TxIndex,
        epoch: Epoch,
        tx: &Transfer,
        shielded: &Transaction,
    ) {
        // For tracking the account changes caused by this Transaction
        let mut transaction_delta = TransactionDelta::new();
        // Listen for notes sent to our viewing keys
        for so in shielded
            .sapling_bundle()
            .map_or(&vec![], |x| &x.shielded_outputs)
        {
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
                    let nf = note.nf(&vk.nk, note_pos.try_into().unwrap());
                    self.note_map.insert(note_pos, note);
                    self.memo_map.insert(note_pos, memo);
                    // The payment address' diversifier is required to spend
                    // note
                    self.div_map.insert(note_pos, *pa.diversifier());
                    self.nf_map.insert(nf, note_pos);
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
        client: &U::C,
        asset_type: AssetType,
    ) -> Option<(Address, Epoch)> {
        // Try to find the decoding in the cache
        if let decoded @ Some(_) = self.asset_types.get(&asset_type) {
            return decoded.cloned();
        }
        // Query for the ID of the last accepted transaction
        let (addr, ep, _conv, _path): (Address, _, Amount, MerklePath<Node>) =
            rpc::query_conversion(client, asset_type).await?;
        self.asset_types.insert(asset_type, (addr.clone(), ep));
        Some((addr, ep))
    }

    /// Query the ledger for the conversion that is allowed for the given asset
    /// type and cache it.
    async fn query_allowed_conversion<'a>(
        &'a mut self,
        client: &U::C,
        asset_type: AssetType,
        conversions: &'a mut Conversions,
    ) -> Option<&'a mut (AllowedConversion, MerklePath<Node>, i64)> {
        match conversions.entry(asset_type) {
            Entry::Occupied(conv_entry) => Some(conv_entry.into_mut()),
            Entry::Vacant(conv_entry) => {
                // Query for the ID of the last accepted transaction
                let (addr, ep, conv, path): (Address, _, _, _) =
                    rpc::query_conversion(client, asset_type).await?;
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
        client: &U::C,
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
        client: &U::C,
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
                .decode_asset_type(client, asset_type)
                .await
                .map(|(addr, _epoch)| make_asset_type(target_epoch, &addr))
                .unwrap_or(asset_type);
            let at_target_asset_type = asset_type == target_asset_type;
            if let (Some((conv, _wit, usage)), false) = (
                self.query_allowed_conversion(
                    client,
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
                    client,
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
        client: &U::C,
        vk: &ViewingKey,
        target: Amount,
        target_epoch: Epoch,
    ) -> (
        Amount,
        Vec<(Diversifier, Note, MerklePath<Node>)>,
        Conversions,
    ) {
        // Establish connection with which to do exchange rate queries
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
                        client,
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
        client: &U::C,
        owner: PaymentAddress,
        viewing_key: &ViewingKey,
    ) -> Result<(Amount, Epoch), PinnedBalanceError> {
        // Check that the supplied viewing key corresponds to given payment
        // address
        let counter_owner = viewing_key.to_payment_address(
            *masp_primitives::sapling::PaymentAddress::diversifier(
                &owner.into(),
            ),
        );
        match counter_owner {
            Some(counter_owner) if counter_owner == owner.into() => {}
            _ => return Err(PinnedBalanceError::InvalidViewingKey),
        }
        // The address of the MASP account
        let masp_addr = masp();
        // Construct the key for where the transaction ID would be stored
        let pin_key = Key::from(masp_addr.to_db_key())
            .push(&(PIN_KEY_PREFIX.to_owned() + &owner.hash()))
            .expect("Cannot obtain a storage key");
        // Obtain the transaction pointer at the key
        let txidx = rpc::query_storage_value::<U::C, u64>(client, &pin_key)
            .await
            .ok_or(PinnedBalanceError::NoTransactionPinned)?;
        // Construct the key for where the pinned transaction is stored
        let tx_key = Key::from(masp_addr.to_db_key())
            .push(&(TX_KEY_PREFIX.to_owned() + &txidx.to_string()))
            .expect("Cannot obtain a storage key");
        // Obtain the pointed to transaction
        let (tx_epoch, _tx_height, _tx_index, _tx, shielded) =
            rpc::query_storage_value::<
                U::C,
                (Epoch, BlockHeight, TxIndex, Transfer, Transaction),
            >(client, &tx_key)
            .await
            .expect("Ill-formed epoch, transaction pair");
        // Accumulate the combined output note value into this Amount
        let mut val_acc = Amount::zero();
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
        client: &U::C,
        owner: PaymentAddress,
        viewing_key: &ViewingKey,
    ) -> Result<(Amount, Epoch), PinnedBalanceError> {
        // Obtain the balance that will be exchanged
        let (amt, ep) =
            Self::compute_pinned_balance(client, owner, viewing_key).await?;
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
        client: &U::C,
        amt: Amount,
        target_epoch: Epoch,
    ) -> Amount<Address> {
        let mut res = Amount::zero();
        for (asset_type, val) in amt.components() {
            // Decode the asset type
            let decoded = self.decode_asset_type(client, *asset_type).await;
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
        client: &U::C,
        amt: Amount,
    ) -> Amount<(Address, Epoch)> {
        let mut res = Amount::zero();
        for (asset_type, val) in amt.components() {
            // Decode the asset type
            let decoded = self.decode_asset_type(client, *asset_type).await;
            // Only assets with the target timestamp count
            if let Some((addr, epoch)) = decoded {
                res += &Amount::from_pair((addr, epoch), *val).unwrap()
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
    #[cfg(feature = "masp-tx-gen")]
    pub async fn gen_shielded_transfer(
        &mut self,
        client: &U::C,
        args: args::TxTransfer,
    ) -> Result<
        Option<(
            Builder<(), (), ExtendedFullViewingKey, ()>,
            Transaction,
            SaplingMetadata,
            Epoch,
        )>,
        builder::Error<std::convert::Infallible>,
    > {
        // No shielded components are needed when neither source nor destination
        // are shielded
        let spending_key = args.source.spending_key();
        let payment_address = args.target.payment_address();
        // No shielded components are needed when neither source nor
        // destination are shielded
        if spending_key.is_none() && payment_address.is_none() {
            return Ok(None);
        }
        // We want to fund our transaction solely from supplied spending key
        let spending_key = spending_key.map(|x| x.into());
        let spending_keys: Vec<_> = spending_key.into_iter().collect();
        // Load the current shielded context given the spending key we possess
        let _ = self.load().await;
        self.fetch(client, &spending_keys, &[]).await;
        // Save the update state so that future fetches can be short-circuited
        let _ = self.save().await;
        // Determine epoch in which to submit potential shielded transaction
        let epoch = rpc::query_epoch(client).await;
        // Context required for storing which notes are in the source's
        // possesion
        let amt: u64 = args.amount.into();
        let memo = MemoBytes::empty();

        // Now we build up the transaction within this object
        let mut builder = Builder::<_, OsRng>::new(NETWORK, 1.into());
        // Convert transaction amount into MASP types
        let (asset_type, amount) =
            convert_amount(epoch, &args.token, args.amount);
        // The fee to be paid for the transaction
        let tx_fee;

        // If there are shielded inputs
        if let Some(sk) = spending_key {
            // Transaction fees need to match the amount in the wrapper Transfer
            // when MASP source is used
            let (_, fee) =
                convert_amount(epoch, &args.tx.fee_token, args.tx.fee_amount);
            tx_fee = fee.clone();
            // Locate unspent notes that can help us meet the transaction amount
            let (_, unspent_notes, used_convs) = self
                .collect_unspent_notes(
                    client,
                    &to_viewing_key(&sk).vk,
                    amount,
                    epoch,
                )
                .await;
            // Commit the notes found to our transaction
            for (diversifier, note, merkle_path) in unspent_notes {
                builder
                    .add_sapling_spend(sk, diversifier, note, merkle_path)
                    .map_err(builder::Error::SaplingBuild)?;
            }
            // Commit the conversion notes used during summation
            for (conv, wit, value) in used_convs.values() {
                if *value > 0 {
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
            // No transfer fees come from the shielded transaction for non-MASP
            // sources
            tx_fee = Amount::zero();
            // We add a dummy UTXO to our transaction, but only the source of
            // the parent Transfer object is used to validate fund
            // availability
            let source_enc = args
                .source
                .address()
                .expect("source address should be transparent")
                .try_to_vec()
                .expect("source address encoding");
            let hash = ripemd::Ripemd160::digest(sha2::Sha256::digest(
                source_enc.as_ref(),
            ));
            let script = TransparentAddress(hash.into());
            builder
                .add_transparent_input(TxOut {
                    asset_type,
                    value: amt.try_into().expect("supplied amount too large"),
                    address: script,
                })
                .map_err(builder::Error::TransparentBuild)?;
        }
        // Now handle the outputs of this transaction
        // If there is a shielded output
        if let Some(pa) = payment_address {
            let ovk_opt = spending_key.map(|x| x.expsk.ovk);
            builder
                .add_sapling_output(
                    ovk_opt,
                    pa.into(),
                    asset_type,
                    amt,
                    memo.clone(),
                )
                .map_err(builder::Error::SaplingBuild)?;
        } else {
            // Embed the transparent target address into the shielded
            // transaction so that it can be signed
            let target_enc = args
                .target
                .address()
                .expect("target address should be transparent")
                .try_to_vec()
                .expect("target address encoding");
            let hash = ripemd::Ripemd160::digest(sha2::Sha256::digest(
                target_enc.as_ref(),
            ));
            builder
                .add_transparent_output(
                    &TransparentAddress(hash.into()),
                    asset_type,
                    amt.try_into().expect("supplied amount too large"),
                )
                .map_err(builder::Error::TransparentBuild)?;
        }

        // Now add outputs representing the change from this payment
        if let Some(sk) = spending_key {
            // Represents the amount of inputs we are short by
            let mut additional = Amount::zero();
            // The change left over from this transaction
            let value_balance = builder
                .value_balance()
                .expect("unable to compute value balance")
                - tx_fee.clone();
            for (asset_type, amt) in value_balance.components() {
                if *amt >= 0 {
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
                } else {
                    // Record how much of the current asset type we are short by
                    additional +=
                        Amount::from_nonnegative(*asset_type, -*amt).unwrap();
                }
            }
            // If we are short by a non-zero amount, then we have insufficient
            // funds
            if additional != Amount::zero() {
                return Err(builder::Error::InsufficientFunds(additional));
            }
        }

        // Build and return the constructed transaction
        builder
            .clone()
            .build(
                &self.utils.local_tx_prover(),
                &FeeRule::non_standard(tx_fee),
            )
            .map(|(tx, metadata)| {
                Some((builder.map_builder(WalletMap), tx, metadata, epoch))
            })
    }

    /// Obtain the known effects of all accepted shielded and transparent
    /// transactions. If an owner is specified, then restrict the set to only
    /// transactions crediting/debiting the given owner. If token is specified,
    /// then restrict set to only transactions involving the given token.
    pub async fn query_tx_deltas(
        &mut self,
        client: &U::C,
        query_owner: &Either<BalanceOwner, Vec<Address>>,
        query_token: &Option<Address>,
        viewing_keys: &HashMap<String, ExtendedViewingKey>,
    ) -> BTreeMap<
        (BlockHeight, TxIndex),
        (Epoch, TransferDelta, TransactionDelta),
    > {
        const TXS_PER_PAGE: u8 = 100;
        let _ = self.load().await;
        let vks = viewing_keys;
        let fvks: Vec<_> = vks
            .values()
            .map(|fvk| ExtendedFullViewingKey::from(*fvk).fvk.vk)
            .collect();
        self.fetch(client, &[], &fvks).await;
        // Save the update state so that future fetches can be short-circuited
        let _ = self.save().await;
        // Required for filtering out rejected transactions from Tendermint
        // responses
        let block_results = rpc::query_results(client).await;
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
                        .expect("Unable to query for transactions")
                        .txs;
                    for response_tx in txs {
                        let height = BlockHeight(response_tx.height.value());
                        let idx = TxIndex(response_tx.index);
                        // Only process yet unprocessed transactions which have
                        // been accepted by node VPs
                        let should_process = !transfers
                            .contains_key(&(height, idx))
                            && block_results[u64::from(height) as usize]
                                .is_accepted(idx.0 as usize);
                        if !should_process {
                            continue;
                        }
                        let tx = Tx::try_from(response_tx.tx.as_ref())
                            .expect("Ill-formed Tx");
                        let mut wrapper = None;
                        let mut transfer = None;
                        extract_payload(tx, &mut wrapper, &mut transfer);
                        // Epoch data is not needed for transparent transactions
                        let epoch =
                            wrapper.map(|x| x.epoch).unwrap_or_default();
                        if let Some(transfer) = transfer {
                            // Skip MASP addresses as they are already handled
                            // by ShieldedContext
                            if transfer.source == masp()
                                || transfer.target == masp()
                            {
                                continue;
                            }
                            // Describe how a Transfer simply subtracts from one
                            // account and adds the same to another
                            let mut delta = TransferDelta::default();
                            let tfer_delta = Amount::from_nonnegative(
                                transfer.token.clone(),
                                u64::from(transfer.amount),
                            )
                            .expect("invalid value for amount");
                            delta.insert(
                                transfer.source,
                                Amount::zero() - &tfer_delta,
                            );
                            delta.insert(transfer.target, tfer_delta);
                            // No shielded accounts are affected by this
                            // Transfer
                            transfers.insert(
                                (height, idx),
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
        transfers
    }
}

/// Extract the payload from the given Tx object
fn extract_payload(
    mut tx: Tx,
    wrapper: &mut Option<WrapperTx>,
    transfer: &mut Option<Transfer>,
) {
    let privkey =
        <EllipticCurve as PairingEngine>::G2Affine::prime_subgroup_generator();
    tx.decrypt(privkey).expect("unable to decrypt transaction");
    *wrapper = tx.header.wrapper();
    let _ = tx.data().map(|signed| {
        Transfer::try_from_slice(&signed[..]).map(|tfer| *transfer = Some(tfer))
    });
}

/// Make asset type corresponding to given address and epoch
pub fn make_asset_type(epoch: Epoch, token: &Address) -> AssetType {
    // Typestamp the chosen token with the current epoch
    let token_bytes = (token, epoch.0)
        .try_to_vec()
        .expect("token should serialize");
    // Generate the unique asset identifier from the unique token address
    AssetType::new(token_bytes.as_ref()).expect("unable to create asset type")
}

/// Convert Anoma amount and token type to MASP equivalents
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
            [SPEND_NAME, CONVERT_NAME, OUTPUT_NAME].map(|p| tempdir.join(p));
        for path in fake_params_paths {
            let mut f =
                std::fs::File::create(path).expect("expected a temp file");
            f.write_all(b"fake params")
                .expect("expected a writable temp file");
            f.sync_all()
                .expect("expected a writable temp file (on sync)");
        }

        std::env::set_var(super::ENV_VAR_MASP_PARAMS_DIR, tempdir.as_os_str());
        // should panic here
        super::load_pvks();
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
            (CONVERT_NAME, 22570940u64),
            (OUTPUT_NAME, 16398620u64),
        ]
        .map(|(p, s)| (tempdir.join(p), s));
        for (path, size) in fake_params_paths {
            let mut f =
                std::fs::File::create(path).expect("expected a temp file");
            fake_params
                .write(&mut f)
                .expect("expected a writable temp file");
            // the dummy circuit has one constraint, and therefore its
            // params should always be smaller than the large masp
            // circuit params. so this truncate extends the file, and
            // extra bytes at the end do not make it invalid.
            f.set_len(size).expect("expected to truncate the temp file");
            f.sync_all()
                .expect("expected a writable temp file (on sync)");
        }

        std::env::set_var(super::ENV_VAR_MASP_PARAMS_DIR, tempdir.as_os_str());
        // should panic here
        super::load_pvks();
    }
}
