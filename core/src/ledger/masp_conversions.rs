//! MASP rewards conversions

use std::collections::BTreeMap;

use borsh::{BorshDeserialize, BorshSerialize};
use borsh_ext::BorshSerializeExt;
use masp_primitives::asset_type::AssetType;
use masp_primitives::convert::AllowedConversion;
use masp_primitives::merkle_tree::FrozenCommitmentTree;
use masp_primitives::sapling::Node;

use crate::ledger::inflation::{RewardsController, ValsToUpdate};
use crate::ledger::parameters;
use crate::ledger::storage::{DBIter, StorageHasher, WlStorage, DB};
use crate::ledger::storage_api::token::read_denom;
use crate::ledger::storage_api::{StorageRead, StorageWrite};
use crate::types::address::{Address, MASP};
use crate::types::dec::Dec;
use crate::types::storage::Epoch;
use crate::types::token::{self, DenominatedAmount, MaspDenom};
use crate::types::uint::Uint;

/// A representation of the conversion state
#[derive(Debug, Default, BorshSerialize, BorshDeserialize)]
pub struct ConversionState {
    /// The last amount of the native token distributed
    pub normed_inflation: Option<u128>,
    /// The tree currently containing all the conversions
    pub tree: FrozenCommitmentTree<Node>,
    /// A map from token alias to actual address.
    pub tokens: BTreeMap<String, Address>,
    /// Map assets to their latest conversion and position in Merkle tree
    #[allow(clippy::type_complexity)]
    pub assets: BTreeMap<
        AssetType,
        ((Address, MaspDenom), Epoch, AllowedConversion, usize),
    >,
}

/// Compute the MASP rewards by applying the PD-controller to the genesis
/// parameters and the last inflation and last locked rewards ratio values.
pub fn calculate_masp_rewards<D, H>(
    wl_storage: &mut WlStorage<D, H>,
    addr: &Address,
) -> crate::ledger::storage_api::Result<(u128, u128)>
where
    D: 'static + DB + for<'iter> DBIter<'iter>,
    H: 'static + StorageHasher,
{
    let denomination = read_denom(wl_storage, addr)?
        .expect("failed to read token denomination");
    // Inflation is implicitly denominated by this value. The lower this
    // figure, the less precise inflation computations are. This is especially
    // problematic when inflation is coming from a token with much higher
    // denomination than the native token. The higher this figure, the higher
    // the threshold of holdings required in order to receive non-zero rewards.
    // This value should be fixed constant for each asset type. Here we choose
    // a thousandth of the given asset.
    let precision = 10u128.pow(std::cmp::max(u32::from(denomination.0), 3) - 3);

    let masp_addr = MASP;
    // Query the storage for information

    //// information about the amount of tokens on the chain
    let total_tokens: token::Amount = wl_storage
        .read(&token::minted_balance_key(addr))?
        .expect("the total supply key should be here");

    //// information about the amount of native tokens on the chain
    let total_native_tokens: token::Amount = wl_storage
        .read(&token::minted_balance_key(&wl_storage.storage.native_token))?
        .expect("the total supply key should be here");

    // total staked amount in the Shielded pool
    let total_token_in_masp: token::Amount = wl_storage
        .read(&token::balance_key(addr, &masp_addr))?
        .unwrap_or_default();

    let epochs_per_year: u64 = wl_storage
        .read(&parameters::storage::get_epochs_per_year_key())?
        .expect("epochs per year should properly decode");

    //// Values from the last epoch
    let last_inflation: token::Amount = wl_storage
        .read(&token::masp_last_inflation_key(addr))?
        .expect("failure to read last inflation");

    let last_locked_ratio: Dec = wl_storage
        .read(&token::masp_last_locked_ratio_key(addr))?
        .expect("failure to read last inflation");

    //// Parameters for each token
    let max_reward_rate: Dec = wl_storage
        .read(&token::masp_max_reward_rate_key(addr))?
        .expect("max reward should properly decode");

    let kp_gain_nom: Dec = wl_storage
        .read(&token::masp_kp_gain_key(addr))?
        .expect("kp_gain_nom reward should properly decode");

    let kd_gain_nom: Dec = wl_storage
        .read(&token::masp_kd_gain_key(addr))?
        .expect("kd_gain_nom reward should properly decode");

    let locked_target_ratio: Dec = wl_storage
        .read(&token::masp_locked_ratio_target_key(addr))?
        .expect("locked ratio target should properly decode");

    // Creating the PD controller for handing out tokens
    let controller = RewardsController {
        locked_tokens: total_token_in_masp.raw_amount(),
        total_tokens: total_tokens.raw_amount(),
        total_native_tokens: total_native_tokens.raw_amount(),
        locked_ratio_target: locked_target_ratio,
        locked_ratio_last: last_locked_ratio,
        max_reward_rate,
        last_inflation_amount: last_inflation.raw_amount(),
        p_gain_nom: kp_gain_nom,
        d_gain_nom: kd_gain_nom,
        epochs_per_year,
    };

    let ValsToUpdate {
        locked_ratio,
        inflation,
    } = RewardsController::run(controller);

    // inflation-per-token = inflation / locked tokens = n/PRECISION
    // ∴ n = (inflation * PRECISION) / locked tokens
    // Since we must put the notes in a compatible format with the
    // note format, we must make the inflation amount discrete.
    let noterized_inflation = if total_token_in_masp.is_zero() {
        0u128
    } else {
        inflation
            .checked_mul_div(
                Uint::from(precision),
                total_token_in_masp.raw_amount(),
            )
            .and_then(|x| x.0.try_into().ok())
            .unwrap_or_else(|| {
                tracing::warn!(
                    "MASP inflation for {} assumed to be 0 because the \
                     computed value is too large. Please check the inflation \
                     parameters.",
                    *addr
                );
                0u128
            })
    };
    let inflation_amount = token::Amount::from_uint(
        (total_token_in_masp.raw_amount() / precision)
            * Uint::from(noterized_inflation),
        0,
    )
    .unwrap();
    let denom_amount = DenominatedAmount::new(inflation_amount, denomination);
    tracing::info!("MASP inflation for {addr} is {denom_amount}");

    tracing::debug!(
        "Controller, call: total_in_masp {:?}, total_tokens {:?}, \
         total_native_tokens {:?}, locked_target_ratio {:?}, \
         last_locked_ratio {:?}, max_reward_rate {:?}, last_inflation {:?}, \
         kp_gain_nom {:?}, kd_gain_nom {:?}, epochs_per_year {:?}",
        total_token_in_masp,
        total_tokens,
        total_native_tokens,
        locked_target_ratio,
        last_locked_ratio,
        max_reward_rate,
        last_inflation,
        kp_gain_nom,
        kd_gain_nom,
        epochs_per_year,
    );
    tracing::debug!("Token address: {:?}", addr);
    tracing::debug!("Ratio {:?}", locked_ratio);
    tracing::debug!("inflation from the pd controller {:?}", inflation);
    tracing::debug!("total in the masp {:?}", total_token_in_masp);
    tracing::debug!("precision {}", precision);
    tracing::debug!("Noterized inflation: {}", noterized_inflation);

    // Is it fine to write the inflation rate, this is accurate,
    // but we should make sure the return value's ratio matches
    // this new inflation rate in 'update_allowed_conversions',
    // otherwise we will have an inaccurate view of inflation
    wl_storage
        .write(&token::masp_last_inflation_key(addr), inflation_amount)?;

    wl_storage.write(&token::masp_last_locked_ratio_key(addr), locked_ratio)?;

    Ok((noterized_inflation, precision))
}

// This is only enabled when "wasm-runtime" is on, because we're using rayon
#[cfg(any(feature = "wasm-runtime", test))]
/// Update the MASP's allowed conversions
pub fn update_allowed_conversions<D, H>(
    wl_storage: &mut WlStorage<D, H>,
) -> crate::ledger::storage_api::Result<()>
where
    D: 'static + DB + for<'iter> DBIter<'iter>,
    H: 'static + StorageHasher,
{
    use std::cmp::Ordering;

    use masp_primitives::bls12_381;
    use masp_primitives::ff::PrimeField;
    use masp_primitives::transaction::components::I128Sum as MaspAmount;
    use rayon::iter::{
        IndexedParallelIterator, IntoParallelIterator, ParallelIterator,
    };
    use rayon::prelude::ParallelSlice;

    use crate::types::address;
    use crate::types::storage::{Key, KeySeg};
    use crate::types::token::MASP_CONVERT_ANCHOR_KEY;

    // The derived conversions will be placed in MASP address space
    let masp_addr = MASP;

    let tokens = address::tokens();
    let mut masp_reward_keys: Vec<_> = tokens
        .into_keys()
        .map(|k| {
            wl_storage
                .storage
                .conversion_state
                .tokens
                .get(k)
                .unwrap_or_else(|| {
                    panic!(
                        "Could not find token alias {} in MASP conversion \
                         state.",
                        k
                    )
                })
                .clone()
        })
        .collect();
    // Put the native rewards first because other inflation computations depend
    // on it
    let native_token = wl_storage.storage.native_token.clone();
    masp_reward_keys.sort_unstable_by(|x, y| {
        if (*x == native_token) == (*y == native_token) {
            Ordering::Equal
        } else if *x == native_token {
            Ordering::Less
        } else {
            Ordering::Greater
        }
    });
    // The total transparent value of the rewards being distributed
    let mut total_reward = token::Amount::native_whole(0);

    // Construct MASP asset type for rewards. Always deflate and timestamp
    // reward tokens with the zeroth epoch to minimize the number of convert
    // notes clients have to use. This trick works under the assumption that
    // reward tokens will then be reinflated back to the current epoch.
    let reward_assets = [
        encode_asset_type(native_token.clone(), MaspDenom::Zero, Epoch(0)),
        encode_asset_type(native_token.clone(), MaspDenom::One, Epoch(0)),
        encode_asset_type(native_token.clone(), MaspDenom::Two, Epoch(0)),
        encode_asset_type(native_token.clone(), MaspDenom::Three, Epoch(0)),
    ];
    // Conversions from the previous to current asset for each address
    let mut current_convs =
        BTreeMap::<(Address, MaspDenom), AllowedConversion>::new();
    // Native token inflation values are always with respect to this
    let mut ref_inflation = 0;
    // Reward all tokens according to above reward rates
    for addr in &masp_reward_keys {
        let reward = calculate_masp_rewards(wl_storage, addr)?;
        if *addr == native_token {
            // The reference inflation is the denominator of the native token
            // inflation, which is always a constant
            ref_inflation = reward.1;
        }
        // Dispense a transparent reward in parallel to the shielded rewards
        let addr_bal: token::Amount = wl_storage
            .read(&token::balance_key(addr, &masp_addr))?
            .unwrap_or_default();
        for denom in token::MaspDenom::iter() {
            // Provide an allowed conversion from previous timestamp. The
            // negative sign allows each instance of the old asset to be
            // cancelled out/replaced with the new asset
            let old_asset = encode_asset_type(
                addr.clone(),
                denom,
                wl_storage.storage.last_epoch,
            );
            let new_asset = encode_asset_type(
                addr.clone(),
                denom,
                wl_storage.storage.block.epoch,
            );
            // Get the last rewarded amount of the native token
            let normed_inflation = wl_storage
                .storage
                .conversion_state
                .normed_inflation
                .get_or_insert(ref_inflation);
            if *addr == native_token {
                // The amount that will be given of the new native token for
                // every amount of the native token given in the
                // previous epoch
                let new_normed_inflation = Uint::from(*normed_inflation)
                    .checked_add(
                        (Uint::from(*normed_inflation) * Uint::from(reward.0))
                            / reward.1,
                    )
                    .and_then(|x| x.try_into().ok())
                    .unwrap_or_else(|| {
                        tracing::warn!(
                            "MASP reward for {} assumed to be 0 because the \
                             computed value is too large. Please check the \
                             inflation parameters.",
                            addr
                        );
                        *normed_inflation
                    });
                // The conversion is computed such that if consecutive
                // conversions are added together, the
                // intermediate native tokens cancel/
                // telescope out
                current_convs.insert(
                    (addr.clone(), denom),
                    (MaspAmount::from_pair(
                        old_asset,
                        -(*normed_inflation as i128),
                    )
                    .unwrap()
                        + MaspAmount::from_pair(
                            new_asset,
                            new_normed_inflation as i128,
                        )
                        .unwrap())
                    .into(),
                );
                // Operations that happen exactly once for each token
                if denom == MaspDenom::Three {
                    // The reward for each reward.1 units of the current asset
                    // is reward.0 units of the reward token
                    total_reward += (addr_bal
                        * (new_normed_inflation, *normed_inflation))
                        .0
                        .checked_sub(addr_bal)
                        .unwrap_or_default();
                    // Save the new normed inflation
                    *normed_inflation = new_normed_inflation;
                }
            } else {
                // Express the inflation reward in real terms, that is, with
                // respect to the native asset in the zeroth
                // epoch
                let real_reward = ((Uint::from(reward.0)
                    * Uint::from(ref_inflation))
                    / *normed_inflation)
                    .try_into()
                    .unwrap_or_else(|_| {
                        tracing::warn!(
                            "MASP reward for {} assumed to be 0 because the \
                             computed value is too large. Please check the \
                             inflation parameters.",
                            addr
                        );
                        0u128
                    });
                // The conversion is computed such that if consecutive
                // conversions are added together, the
                // intermediate tokens cancel/ telescope out
                current_convs.insert(
                    (addr.clone(), denom),
                    (MaspAmount::from_pair(old_asset, -(reward.1 as i128))
                        .unwrap()
                        + MaspAmount::from_pair(new_asset, reward.1 as i128)
                            .unwrap()
                        + MaspAmount::from_pair(
                            reward_assets[denom as usize],
                            real_reward as i128,
                        )
                        .unwrap())
                    .into(),
                );
                // Operations that happen exactly once for each token
                if denom == MaspDenom::Three {
                    // The reward for each reward.1 units of the current asset
                    // is reward.0 units of the reward token
                    total_reward += ((addr_bal * (real_reward, reward.1)).0
                        * (*normed_inflation, ref_inflation))
                        .0;
                }
            }
            // Add a conversion from the previous asset type
            wl_storage.storage.conversion_state.assets.insert(
                old_asset,
                (
                    (addr.clone(), denom),
                    wl_storage.storage.last_epoch,
                    MaspAmount::zero().into(),
                    0,
                ),
            );
        }
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
        .map(|(idx, (asset, _epoch, conv, pos))| {
            // Use transitivity to update conversion
            *conv += current_convs[asset].clone();
            // Update conversion position to leaf we are about to create
            *pos = idx;
            // The merkle tree need only provide the conversion commitment,
            // the remaining information is provided through the storage API
            Node::new(conv.cmu().to_repr())
        })
        .collect();

    // Update the MASP's transparent reward token balance to ensure that it
    // is sufficiently backed to redeem rewards
    let reward_key = token::balance_key(&native_token, &masp_addr);
    let addr_bal: token::Amount =
        wl_storage.read(&reward_key)?.unwrap_or_default();
    let new_bal = addr_bal + total_reward;
    wl_storage.write(&reward_key, new_bal)?;
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

    // Convert conversion vector into tree so that Merkle paths can be
    // obtained
    wl_storage.storage.conversion_state.tree =
        FrozenCommitmentTree::merge(&tree_parts);
    // Update the anchor in storage
    let anchor_key = Key::from(MASP.to_db_key())
        .push(&MASP_CONVERT_ANCHOR_KEY.to_owned())
        .expect("Cannot obtain a storage key");
    wl_storage.write(
        &anchor_key,
        crate::types::hash::Hash(
            bls12_381::Scalar::from(
                wl_storage.storage.conversion_state.tree.root(),
            )
            .to_bytes(),
        ),
    )?;

    // Add purely decoding entries to the assets map. These will be
    // overwritten before the creation of the next commitment tree
    for addr in masp_reward_keys {
        for denom in token::MaspDenom::iter() {
            // Add the decoding entry for the new asset type. An uncommited
            // node position is used since this is not a conversion.
            let new_asset = encode_asset_type(
                addr.clone(),
                denom,
                wl_storage.storage.block.epoch,
            );
            wl_storage.storage.conversion_state.assets.insert(
                new_asset,
                (
                    (addr.clone(), denom),
                    wl_storage.storage.block.epoch,
                    MaspAmount::zero().into(),
                    wl_storage.storage.conversion_state.tree.size(),
                ),
            );
        }
    }

    Ok(())
}

/// Construct MASP asset type with given epoch for given token
pub fn encode_asset_type(
    addr: Address,
    denom: MaspDenom,
    epoch: Epoch,
) -> AssetType {
    let new_asset_bytes = (addr, denom, epoch.0).serialize_to_vec();
    AssetType::new(new_asset_bytes.as_ref())
        .expect("unable to derive asset identifier")
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::str::FromStr;

    use proptest::prelude::*;
    use proptest::test_runner::Config;
    use test_log::test;

    use super::*;
    use crate::ledger::parameters::{EpochDuration, Parameters};
    use crate::ledger::storage::testing::TestWlStorage;
    use crate::ledger::storage_api::token::write_denom;
    use crate::types::address;
    use crate::types::dec::testing::arb_non_negative_dec;
    use crate::types::time::DurationSecs;
    use crate::types::token::testing::arb_amount;

    proptest! {
        #![proptest_config(Config {
            cases: 10,
            .. Config::default()
        })]
        #[test]
        fn test_updated_allowed_conversions(
            initial_balance in arb_amount(),
            masp_locked_ratio in arb_non_negative_dec(),
        ) {
            test_updated_allowed_conversions_aux(initial_balance, masp_locked_ratio)
        }
    }

    fn test_updated_allowed_conversions_aux(
        initial_balance: token::Amount,
        masp_locked_ratio: Dec,
    ) {
        const ROUNDS: usize = 10;

        let mut s = TestWlStorage::default();
        let params = Parameters {
            max_tx_bytes: 1024 * 1024,
            epoch_duration: EpochDuration {
                min_num_of_blocks: 1,
                min_duration: DurationSecs(3600),
            },
            max_expected_time_per_block: DurationSecs(3600),
            max_proposal_bytes: Default::default(),
            max_block_gas: 100,
            vp_whitelist: vec![],
            tx_whitelist: vec![],
            implicit_vp_code_hash: Default::default(),
            epochs_per_year: 365,
            max_signatures_per_transaction: 10,
            staked_ratio: Default::default(),
            pos_inflation_amount: Default::default(),
            fee_unshielding_gas_limit: 0,
            fee_unshielding_descriptions_limit: 0,
            minimum_gas_price: Default::default(),
        };

        // Initialize the state
        {
            // Parameters
            params.init_storage(&mut s).unwrap();

            // Tokens
            let token_params = token::Parameters {
                max_reward_rate: Dec::from_str("0.1").unwrap(),
                kp_gain_nom: Dec::from_str("0.1").unwrap(),
                kd_gain_nom: Dec::from_str("0.1").unwrap(),
                locked_ratio_target: Dec::from_str("0.6667").unwrap(),
            };

            for (token_addr, (alias, denom)) in tokens() {
                token_params.init_storage(&token_addr, &mut s);

                write_denom(&mut s, &token_addr, denom).unwrap();

                // Write a minted token balance
                let total_token_balance = initial_balance;
                s.write(
                    &token::minted_balance_key(&token_addr),
                    total_token_balance,
                )
                .unwrap();

                // Put the locked ratio into MASP
                s.write(
                    &token::balance_key(&token_addr, &address::MASP),
                    masp_locked_ratio * total_token_balance,
                )
                .unwrap();

                // Insert tokens into MASP conversion state
                s.storage
                    .conversion_state
                    .tokens
                    .insert(alias.to_string(), token_addr.clone());
            }
        }

        for i in 0..ROUNDS {
            println!("Round {i}");
            update_allowed_conversions(&mut s).unwrap();
            println!();
            println!();
        }
    }

    pub fn tokens() -> HashMap<Address, (&'static str, token::Denomination)> {
        vec![
            (address::nam(), ("nam", 6.into())),
            (address::btc(), ("btc", 8.into())),
            (address::eth(), ("eth", 18.into())),
            (address::dot(), ("dot", 10.into())),
            (address::schnitzel(), ("schnitzel", 6.into())),
            (address::apfel(), ("apfel", 6.into())),
            (address::kartoffel(), ("kartoffel", 6.into())),
        ]
        .into_iter()
        .collect()
    }
}
