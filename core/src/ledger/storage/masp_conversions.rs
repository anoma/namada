//! MASP rewards conversions

use std::collections::BTreeMap;

use borsh::{BorshDeserialize, BorshSerialize};
use masp_primitives::asset_type::AssetType;
use masp_primitives::convert::AllowedConversion;
use masp_primitives::merkle_tree::FrozenCommitmentTree;
use masp_primitives::sapling::Node;

use crate::types::address::Address;
use crate::types::storage::Epoch;

/// A representation of the conversion state
#[derive(Debug, Default, BorshSerialize, BorshDeserialize)]
pub struct ConversionState {
    /// The merkle root from the previous epoch
    pub prev_root: Node,
    /// The tree currently containing all the conversions
    pub tree: FrozenCommitmentTree<Node>,
    /// Map assets to their latest conversion and position in Merkle tree
    pub assets: BTreeMap<AssetType, (Address, Epoch, AllowedConversion, usize)>,
}

// This is only enabled when "wasm-runtime" is on, because we're using rayon
#[cfg(feature = "wasm-runtime")]
/// Update the MASP's allowed conversions
pub fn update_allowed_conversions<D, H>(
    wl_storage: &mut super::WlStorage<D, H>,
) -> crate::ledger::storage_api::Result<()>
where
    D: super::DB + for<'iter> super::DBIter<'iter>,
    H: super::StorageHasher,
{
    use masp_primitives::ff::PrimeField;
    use masp_primitives::transaction::components::Amount as MaspAmount;
    use rayon::iter::{
        IndexedParallelIterator, IntoParallelIterator, ParallelIterator,
    };
    use rayon::prelude::ParallelSlice;

    use crate::ledger::inflation::mint_tokens;
    use crate::ledger::storage_api::{ResultExt, StorageRead, StorageWrite};
    use crate::types::storage::{self, KeySeg};
    use crate::types::{address, token};

    // The derived conversions will be placed in MASP address space
    let masp_addr = address::masp();
    let key_prefix: storage::Key = masp_addr.to_db_key().into();

    let masp_rewards = address::masp_rewards();
    // The total transparent value of the rewards being distributed
    let mut total_reward = token::Amount::from(0);

    // Construct MASP asset type for rewards. Always timestamp reward tokens
    // with the zeroth epoch to minimize the number of convert notes clients
    // have to use. This trick works under the assumption that reward tokens
    // from different epochs are exactly equivalent.
    let reward_asset_bytes = (address::nam(), 0u64)
        .try_to_vec()
        .expect("unable to serialize address and epoch");
    let reward_asset = AssetType::new(reward_asset_bytes.as_ref())
        .expect("unable to derive asset identifier");
    // Conversions from the previous to current asset for each address
    let mut current_convs = BTreeMap::<Address, AllowedConversion>::new();
    // Reward all tokens according to above reward rates
    for (addr, reward) in &masp_rewards {
        // Dispence a transparent reward in parallel to the shielded rewards
        let addr_bal: token::Amount = wl_storage
            .read(&token::balance_key(addr, &masp_addr))?
            .unwrap_or_default();
        // The reward for each reward.1 units of the current asset is
        // reward.0 units of the reward token
        // Since floor(a) + floor(b) <= floor(a+b), there will always be
        // enough rewards to reimburse users
        total_reward += (addr_bal * *reward).0;
        // Provide an allowed conversion from previous timestamp. The
        // negative sign allows each instance of the old asset to be
        // cancelled out/replaced with the new asset
        let old_asset =
            encode_asset_type(addr.clone(), wl_storage.storage.last_epoch);
        let new_asset =
            encode_asset_type(addr.clone(), wl_storage.storage.block.epoch);
        current_convs.insert(
            addr.clone(),
            (MaspAmount::from_pair(old_asset, -(reward.1 as i64)).unwrap()
                + MaspAmount::from_pair(new_asset, reward.1).unwrap()
                + MaspAmount::from_pair(reward_asset, reward.0).unwrap())
            .into(),
        );
        // Add a conversion from the previous asset type
        wl_storage.storage.conversion_state.assets.insert(
            old_asset,
            (
                addr.clone(),
                wl_storage.storage.last_epoch,
                MaspAmount::zero().into(),
                0,
            ),
        );
    }

    // Try to distribute Merkle leaf updating as evenly as possible across
    // multiple cores
    let num_threads = rayon::current_num_threads();
    // Put assets into vector to enable computation batching
    let assets: Vec<_> = wl_storage
        .storage
        .conversion_state
        .assets
        .values_mut()
        .enumerate()
        .collect();
    // ceil(assets.len() / num_threads)
    let notes_per_thread_max = (assets.len() - 1) / num_threads + 1;
    // floor(assets.len() / num_threads)
    let notes_per_thread_min = assets.len() / num_threads;
    // Now on each core, add the latest conversion to each conversion
    let conv_notes: Vec<Node> = assets
        .into_par_iter()
        .with_min_len(notes_per_thread_min)
        .with_max_len(notes_per_thread_max)
        .map(|(idx, (addr, _epoch, conv, pos))| {
            // Use transitivity to update conversion
            *conv += current_convs[addr].clone();
            // Update conversion position to leaf we are about to create
            *pos = idx;
            // The merkle tree need only provide the conversion commitment,
            // the remaining information is provided through the storage API
            Node::new(conv.cmu().to_repr())
        })
        .collect();

    // Update the MASP's transparent reward token balance to ensure that it
    // is sufficiently backed to redeem rewards
    mint_tokens(wl_storage, &masp_addr, &address::nam(), total_reward)?;

    // Try to distribute Merkle tree construction as evenly as possible
    // across multiple cores
    // Merkle trees must have exactly 2^n leaves to be mergeable
    let mut notes_per_thread_rounded = 1;
    while notes_per_thread_max > notes_per_thread_rounded * 4 {
        notes_per_thread_rounded *= 2;
    }
    // Make the sub-Merkle trees in parallel
    let tree_parts: Vec<_> = conv_notes
        .par_chunks(notes_per_thread_rounded)
        .map(FrozenCommitmentTree::new)
        .collect();

    // Keep the merkle root from the old tree for transactions constructed
    // close to the epoch boundary
    wl_storage.storage.conversion_state.prev_root =
        wl_storage.storage.conversion_state.tree.root();

    // Convert conversion vector into tree so that Merkle paths can be
    // obtained
    wl_storage.storage.conversion_state.tree =
        FrozenCommitmentTree::merge(&tree_parts);

    // Add purely decoding entries to the assets map. These will be
    // overwritten before the creation of the next commitment tree
    for addr in masp_rewards.keys() {
        // Add the decoding entry for the new asset type. An uncommited
        // node position is used since this is not a conversion.
        let new_asset =
            encode_asset_type(addr.clone(), wl_storage.storage.block.epoch);
        wl_storage.storage.conversion_state.assets.insert(
            new_asset,
            (
                addr.clone(),
                wl_storage.storage.block.epoch,
                MaspAmount::zero().into(),
                wl_storage.storage.conversion_state.tree.size(),
            ),
        );
    }

    // Save the current conversion state in order to avoid computing
    // conversion commitments from scratch in the next epoch
    let state_key = key_prefix
        .push(&(token::CONVERSION_KEY_PREFIX.to_owned()))
        .into_storage_result()?;
    // We cannot borrow `conversion_state` at the same time as when we call
    // `wl_storage.write`, so we encode it manually first
    let conv_bytes = wl_storage
        .storage
        .conversion_state
        .try_to_vec()
        .into_storage_result()?;
    wl_storage.write_bytes(&state_key, conv_bytes)?;
    Ok(())
}

/// Construct MASP asset type with given epoch for given token
pub fn encode_asset_type(addr: Address, epoch: Epoch) -> AssetType {
    let new_asset_bytes = (addr, epoch.0)
        .try_to_vec()
        .expect("unable to serialize address and epoch");
    AssetType::new(new_asset_bytes.as_ref())
        .expect("unable to derive asset identifier")
}
