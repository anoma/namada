//! MASP rewards conversions

use std::collections::BTreeMap;

use borsh::{BorshDeserialize, BorshSerialize};
use masp_primitives::asset_type::AssetType;
use masp_primitives::convert::AllowedConversion;
use masp_primitives::merkle_tree::FrozenCommitmentTree;
use masp_primitives::sapling::Node;

use crate::ledger::inflation::{mint_tokens, RewardsController, ValsToUpdate};
use crate::ledger::parameters;
use crate::ledger::storage_api::{ResultExt, StorageRead, StorageWrite};
use crate::types::address::Address;
use crate::types::storage::Epoch;
use crate::types::{address, token};

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

fn calculate_masp_rewards<D, H>(
    wl_storage: &mut super::WlStorage<D, H>,
    addr: &Address,
) -> crate::ledger::storage_api::Result<(u64, u64)>
where
    D: super::DB + for<'iter> super::DBIter<'iter>,
    H: super::StorageHasher,
{
    use rust_decimal::Decimal;

    let masp_addr = address::masp();
    // Query the storage for information

    //// information about the amount of tokens on the chain
    let total_tokens: token::Amount =
        wl_storage.read(&token::total_supply_key(addr))?.expect("");

    // total staked amount in the Shielded pool
    let total_token_in_masp: token::Amount = wl_storage
        .read(&token::balance_key(addr, &masp_addr))?
        .expect("");

    let epochs_per_year: u64 = wl_storage
        .read(&parameters::storage::get_epochs_per_year_key())?
        .expect("");

    //// Values from the last epoch
    let last_inflation: u64 = wl_storage
        .read(&token::last_inflation(addr))
        .expect("failure to read last inflation")
        .expect("");

    let last_locked_ratio: Decimal = wl_storage
        .read(&token::last_locked_ratio(addr))
        .expect("failure to read last inflation")
        .expect("");

    //// Parameters for each token
    let max_reward_rate: Decimal = wl_storage
        .read(&token::parameters::max_reward_rate(addr))
        .expect("max reward should properly decode")
        .expect("");

    let kp_gain_nom: Decimal = wl_storage
        .read(&token::parameters::kp_sp_gain(addr))
        .expect("kp_gain_nom reward should properly decode")
        .expect("");

    let kd_gain_nom: Decimal = wl_storage
        .read(&token::parameters::kd_sp_gain(addr))
        .expect("kd_gain_nom reward should properly decode")
        .expect("");

    let locked_target_ratio: Decimal = wl_storage
        .read(&token::parameters::locked_token_ratio(addr))?
        .expect("");

    // Creating the PD controller for handing out tokens
    let controller = RewardsController::new(
        total_token_in_masp,
        total_tokens,
        locked_target_ratio,
        last_locked_ratio,
        max_reward_rate,
        token::Amount::from(last_inflation),
        kp_gain_nom,
        kd_gain_nom,
        epochs_per_year,
    );

    let ValsToUpdate {
        locked_ratio,
        inflation,
    } = RewardsController::run(&controller);

    // Is it fine to write the inflation rate, this is accurate,
    // but we should make sure the return value's ratio matches
    // this new inflation rate in 'update_allowed_conversions',
    // otherwise we will have an inaccurate view of inflation
    wl_storage
        .write(&token::last_inflation(addr), inflation)
        .expect("unable to encode new inflation rate (Decimal)");

    wl_storage
        .write(&token::last_locked_ratio(addr), locked_ratio)
        .expect("unable to encode new locked ratio (Decimal)");

    // to make it conform with the expected output, we need to
    // move it to a ratio of x/100 to match the masp_rewards
    // function This may be unneeded, as we could describe it as a
    // ratio of x/1

    // inflation-per-token = inflation / locked tokens = n/100
    // ∴ n = (inflation * 100) / locked tokens
    let total_in = total_token_in_masp.change() as u64;
    if 0u64 == total_in {
        Ok((0u64, 100))
    } else {
        Ok((inflation * 100 / total_token_in_masp.change() as u64, 100))
    }
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

    use crate::types::storage::{self, KeySeg};

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
    for addr in masp_rewards.keys() {
        let reward = calculate_masp_rewards(wl_storage, addr)
            .expect("Calculating the masp rewards should not fail");
        // Dispence a transparent reward in parallel to the shielded rewards
        let addr_bal: token::Amount = wl_storage
            .read(&token::balance_key(addr, &masp_addr))?
            .unwrap_or_default();
        // The reward for each reward.1 units of the current asset is
        // reward.0 units of the reward token
        // Since floor(a) + floor(b) <= floor(a+b), there will always be
        // enough rewards to reimburse users
        total_reward += (addr_bal * reward).0;
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
