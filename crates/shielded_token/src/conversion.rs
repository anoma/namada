//! MASP rewards conversions

#[cfg(any(feature = "multicore", test))]
use namada_core::borsh::BorshSerializeExt;
use namada_core::ledger::inflation::{
    ShieldedRewardsController, ShieldedValsToUpdate,
};
use namada_core::types::address::{Address, MASP};
use namada_core::types::dec::Dec;
#[cfg(any(feature = "multicore", test))]
use namada_core::types::hash::Hash;
#[cfg(any(feature = "multicore", test))]
use namada_core::types::masp::TokenMap;
use namada_core::types::uint::Uint;
use namada_parameters as parameters;
use namada_state::{DBIter, StorageHasher, WlStorage, DB};
use namada_storage::{StorageRead, StorageWrite};
use namada_trans_token::storage_key::{balance_key, minted_balance_key};
use namada_trans_token::{read_denom, Amount, DenominatedAmount, Denomination};

#[cfg(any(feature = "multicore", test))]
use crate::storage_key::{masp_assets_hash_key, masp_token_map_key};
use crate::storage_key::{
    masp_kd_gain_key, masp_kp_gain_key, masp_last_inflation_key,
    masp_last_locked_amount_key, masp_locked_amount_target_key,
    masp_max_reward_rate_key,
};

/// Compute the precision of MASP rewards for the given token. This function
/// must be a non-zero constant for a given token.
pub fn calculate_masp_rewards_precision<D, H>(
    wl_storage: &mut WlStorage<D, H>,
    addr: &Address,
) -> namada_storage::Result<(u128, Denomination)>
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
    Ok((
        10u128.pow(std::cmp::max(u32::from(denomination.0), 3) - 3),
        denomination,
    ))
}

/// Compute the MASP rewards by applying the PD-controller to the genesis
/// parameters and the last inflation and last locked rewards ratio values.
pub fn calculate_masp_rewards<D, H>(
    wl_storage: &mut WlStorage<D, H>,
    token: &Address,
) -> namada_storage::Result<((u128, u128), Denomination)>
where
    D: 'static + DB + for<'iter> DBIter<'iter>,
    H: 'static + StorageHasher,
{
    let (precision, denomination) =
        calculate_masp_rewards_precision(wl_storage, token)?;

    let masp_addr = MASP;

    // Query the storage for information -------------------------

    //// information about the amount of native tokens on the chain
    let total_native_tokens: Amount = wl_storage
        .read(&minted_balance_key(&wl_storage.storage.native_token))?
        .expect("the total supply key should be here");

    // total locked amount in the Shielded pool
    let total_tokens_in_masp: Amount = wl_storage
        .read(&balance_key(token, &masp_addr))?
        .unwrap_or_default();

    let epochs_per_year: u64 = wl_storage
        .read(&parameters::storage::get_epochs_per_year_key())?
        .expect("epochs per year should properly decode");

    //// Values from the last epoch
    let last_inflation: Amount = wl_storage
        .read(&masp_last_inflation_key(token))?
        .expect("failure to read last inflation");

    let last_locked_amount: Amount = wl_storage
        .read(&masp_last_locked_amount_key(token))?
        .expect("failure to read last inflation");

    //// Parameters for each token
    let max_reward_rate: Dec = wl_storage
        .read(&masp_max_reward_rate_key(token))?
        .expect("max reward should properly decode");

    let kp_gain_nom: Dec = wl_storage
        .read(&masp_kp_gain_key(token))?
        .expect("kp_gain_nom reward should properly decode");

    let kd_gain_nom: Dec = wl_storage
        .read(&masp_kd_gain_key(token))?
        .expect("kd_gain_nom reward should properly decode");

    let target_locked_amount: Amount = wl_storage
        .read(&masp_locked_amount_target_key(token))?
        .expect("locked ratio target should properly decode");

    // Creating the PD controller for handing out tokens
    let controller = ShieldedRewardsController {
        locked_tokens: total_tokens_in_masp.raw_amount(),
        total_native_tokens: total_native_tokens.raw_amount(),
        locked_tokens_target: target_locked_amount.raw_amount(),
        locked_tokens_last: last_locked_amount.raw_amount(),
        max_reward_rate,
        last_inflation_amount: last_inflation.raw_amount(),
        p_gain_nom: kp_gain_nom,
        d_gain_nom: kd_gain_nom,
        epochs_per_year,
    };

    let ShieldedValsToUpdate { inflation } =
        ShieldedRewardsController::run(controller);

    // inflation-per-token = inflation / locked tokens = n/PRECISION
    // ∴ n = (inflation * PRECISION) / locked tokens
    // Since we must put the notes in a compatible format with the
    // note format, we must make the inflation amount discrete.
    let noterized_inflation = if total_tokens_in_masp.is_zero() {
        0u128
    } else {
        inflation
            .checked_mul_div(
                Uint::from(precision),
                total_tokens_in_masp.raw_amount(),
            )
            .and_then(|x| x.0.try_into().ok())
            .unwrap_or_else(|| {
                tracing::warn!(
                    "MASP inflation for {} assumed to be 0 because the \
                     computed value is too large. Please check the inflation \
                     parameters.",
                    *token
                );
                0u128
            })
    };
    let inflation_amount = Amount::from_uint(
        (total_tokens_in_masp.raw_amount() / precision)
            * Uint::from(noterized_inflation),
        0,
    )
    .unwrap();
    let denom_amount = DenominatedAmount::new(inflation_amount, denomination);
    tracing::info!("MASP inflation for {token} is {denom_amount}");

    tracing::debug!(
        "Controller, call: total_in_masp {:?}, total_native_tokens {:?}, \
         locked_target_amount {:?}, last_locked_amount {:?}, max_reward_rate \
         {:?}, last_inflation {:?}, kp_gain_nom {:?}, kd_gain_nom {:?}, \
         epochs_per_year {:?}",
        total_tokens_in_masp,
        total_native_tokens,
        target_locked_amount,
        last_locked_amount,
        max_reward_rate,
        last_inflation,
        kp_gain_nom,
        kd_gain_nom,
        epochs_per_year,
    );
    tracing::debug!("Token address: {:?}", token);
    tracing::debug!("inflation from the pd controller {:?}", inflation);
    tracing::debug!("total in the masp {:?}", total_tokens_in_masp);
    tracing::debug!("precision {}", precision);
    tracing::debug!("Noterized inflation: {}", noterized_inflation);

    // Is it fine to write the inflation rate, this is accurate,
    // but we should make sure the return value's ratio matches
    // this new inflation rate in 'update_allowed_conversions',
    // otherwise we will have an inaccurate view of inflation
    wl_storage.write(&masp_last_inflation_key(token), inflation_amount)?;

    wl_storage
        .write(&masp_last_locked_amount_key(token), total_tokens_in_masp)?;

    Ok(((noterized_inflation, precision), denomination))
}

// This is only enabled when "wasm-runtime" is on, because we're using rayon
#[cfg(any(feature = "multicore", test))]
/// Update the MASP's allowed conversions
pub fn update_allowed_conversions<D, H>(
    wl_storage: &mut WlStorage<D, H>,
) -> namada_storage::Result<()>
where
    D: 'static + DB + for<'iter> DBIter<'iter>,
    H: 'static + StorageHasher,
{
    use std::cmp::Ordering;
    use std::collections::BTreeMap;

    use masp_primitives::bls12_381;
    use masp_primitives::convert::AllowedConversion;
    use masp_primitives::ff::PrimeField;
    use masp_primitives::merkle_tree::FrozenCommitmentTree;
    use masp_primitives::sapling::Node;
    use masp_primitives::transaction::components::I128Sum as MaspAmount;
    use namada_core::types::masp::encode_asset_type;
    use namada_core::types::storage::Epoch;
    use namada_storage::ResultExt;
    use namada_trans_token::{MaspDigitPos, NATIVE_MAX_DECIMAL_PLACES};
    use rayon::iter::{
        IndexedParallelIterator, IntoParallelIterator, ParallelIterator,
    };
    use rayon::prelude::ParallelSlice;

    // The derived conversions will be placed in MASP address space
    let masp_addr = MASP;

    let token_map_key = masp_token_map_key();
    let token_map: TokenMap =
        wl_storage.read(&token_map_key)?.unwrap_or_default();
    let mut masp_reward_keys: Vec<_> = token_map.values().cloned().collect();
    let mut masp_reward_denoms = BTreeMap::new();
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
    let mut total_reward = Amount::native_whole(0);

    // Construct MASP asset type for rewards. Always deflate and timestamp
    // reward tokens with the zeroth epoch to minimize the number of convert
    // notes clients have to use. This trick works under the assumption that
    // reward tokens will then be reinflated back to the current epoch.
    let reward_assets = [
        encode_asset_type(
            native_token.clone(),
            NATIVE_MAX_DECIMAL_PLACES.into(),
            MaspDigitPos::Zero,
            Some(Epoch(0)),
        )
        .into_storage_result()?,
        encode_asset_type(
            native_token.clone(),
            NATIVE_MAX_DECIMAL_PLACES.into(),
            MaspDigitPos::One,
            Some(Epoch(0)),
        )
        .into_storage_result()?,
        encode_asset_type(
            native_token.clone(),
            NATIVE_MAX_DECIMAL_PLACES.into(),
            MaspDigitPos::Two,
            Some(Epoch(0)),
        )
        .into_storage_result()?,
        encode_asset_type(
            native_token.clone(),
            NATIVE_MAX_DECIMAL_PLACES.into(),
            MaspDigitPos::Three,
            Some(Epoch(0)),
        )
        .into_storage_result()?,
    ];
    // Conversions from the previous to current asset for each address
    let mut current_convs = BTreeMap::<
        (Address, Denomination, MaspDigitPos),
        AllowedConversion,
    >::new();
    // Native token inflation values are always with respect to this
    let ref_inflation =
        calculate_masp_rewards_precision(wl_storage, &native_token)?.0;

    // Reward all tokens according to above reward rates
    for token in &masp_reward_keys {
        let (reward, denom) = calculate_masp_rewards(wl_storage, token)?;
        masp_reward_denoms.insert(token.clone(), denom);
        // Dispense a transparent reward in parallel to the shielded rewards
        let addr_bal: Amount = wl_storage
            .read(&balance_key(token, &masp_addr))?
            .unwrap_or_default();
        // Get the last rewarded amount of the native token
        let normed_inflation = wl_storage
            .storage
            .conversion_state
            .normed_inflation
            .get_or_insert(ref_inflation);

        for digit in MaspDigitPos::iter() {
            // Provide an allowed conversion from previous timestamp. The
            // negative sign allows each instance of the old asset to be
            // cancelled out/replaced with the new asset
            let old_asset = encode_asset_type(
                token.clone(),
                denom,
                digit,
                Some(wl_storage.storage.last_epoch),
            )
            .into_storage_result()?;
            let new_asset = encode_asset_type(
                token.clone(),
                denom,
                digit,
                Some(wl_storage.storage.block.epoch),
            )
            .into_storage_result()?;
            if *token == native_token {
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
                            token
                        );
                        *normed_inflation
                    });
                // The conversion is computed such that if consecutive
                // conversions are added together, the
                // intermediate native tokens cancel/
                // telescope out
                current_convs.insert(
                    (token.clone(), denom, digit),
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
                if digit == MaspDigitPos::Three {
                    // The reward for each reward.1 units of the current asset
                    // is reward.0 units of the reward token
                    let native_reward =
                        addr_bal * (new_normed_inflation, *normed_inflation);
                    total_reward += native_reward
                        .0
                        .checked_add(native_reward.1)
                        .unwrap_or(Amount::max())
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
                            token
                        );
                        0u128
                    });
                // The conversion is computed such that if consecutive
                // conversions are added together, the
                // intermediate tokens cancel/ telescope out
                current_convs.insert(
                    (token.clone(), denom, digit),
                    (MaspAmount::from_pair(old_asset, -(reward.1 as i128))
                        .unwrap()
                        + MaspAmount::from_pair(new_asset, reward.1 as i128)
                            .unwrap()
                        + MaspAmount::from_pair(
                            reward_assets[digit as usize],
                            real_reward as i128,
                        )
                        .unwrap())
                    .into(),
                );
                // Operations that happen exactly once for each token
                if digit == MaspDigitPos::Three {
                    // The reward for each reward.1 units of the current asset
                    // is reward.0 units of the reward token
                    total_reward += (addr_bal * (reward.0, reward.1)).0;
                }
            }
            // Add a conversion from the previous asset type
            wl_storage.storage.conversion_state.assets.insert(
                old_asset,
                (
                    (token.clone(), denom, digit),
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
    let notes_per_thread_max = (assets.len() + num_threads - 1) / num_threads;
    // floor(assets.len() / num_threads)
    let notes_per_thread_min = assets.len() / num_threads;
    // Now on each core, add the latest conversion to each conversion
    let conv_notes: Vec<Node> = assets
        .into_par_iter()
        .with_min_len(notes_per_thread_min)
        .with_max_len(notes_per_thread_max)
        .map(|(idx, (asset, _epoch, conv, pos))| {
            if let Some(current_conv) = current_convs.get(asset) {
                // Use transitivity to update conversion
                *conv += current_conv.clone();
            }
            // Update conversion position to leaf we are about to create
            *pos = idx;
            // The merkle tree need only provide the conversion commitment,
            // the remaining information is provided through the storage API
            Node::new(conv.cmu().to_repr())
        })
        .collect();

    // Update the MASP's transparent reward token balance to ensure that it
    // is sufficiently backed to redeem rewards
    let reward_key = balance_key(&native_token, &masp_addr);
    let addr_bal: Amount = wl_storage.read(&reward_key)?.unwrap_or_default();
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
    wl_storage.write(
        &crate::storage_key::masp_convert_anchor_key(),
        namada_core::types::hash::Hash(
            bls12_381::Scalar::from(
                wl_storage.storage.conversion_state.tree.root(),
            )
            .to_bytes(),
        ),
    )?;

    if !masp_reward_keys.contains(&native_token) {
        // Since MASP rewards are denominated in NAM tokens, ensure that clients
        // are able to decode them.
        masp_reward_keys.push(native_token.clone());
    }
    // Add purely decoding entries to the assets map. These will be
    // overwritten before the creation of the next commitment tree
    for (addr, denom) in masp_reward_denoms {
        for digit in MaspDigitPos::iter() {
            // Add the decoding entry for the new asset type. An uncommitted
            // node position is used since this is not a conversion.
            let new_asset = encode_asset_type(
                addr.clone(),
                denom,
                digit,
                Some(wl_storage.storage.block.epoch),
            )
            .into_storage_result()?;
            wl_storage.storage.conversion_state.assets.insert(
                new_asset,
                (
                    (addr.clone(), denom, digit),
                    wl_storage.storage.block.epoch,
                    MaspAmount::zero().into(),
                    wl_storage.storage.conversion_state.tree.size(),
                ),
            );
        }
    }
    // store only the assets hash because the size is quite large
    let assets_hash = Hash::sha256(
        wl_storage
            .storage
            .conversion_state
            .assets
            .serialize_to_vec(),
    );
    wl_storage.write(&masp_assets_hash_key(), assets_hash)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::str::FromStr;

    use namada_core::types::address;
    use namada_core::types::dec::testing::arb_non_negative_dec;
    use namada_core::types::time::DurationSecs;
    use namada_core::types::token::testing::arb_amount;
    use namada_parameters::{EpochDuration, Parameters};
    use namada_state::testing::TestWlStorage;
    use namada_trans_token::{write_denom, Denomination, MaspParams};
    use proptest::prelude::*;
    use proptest::test_runner::Config;
    use test_log::test;

    use super::*;

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
        initial_balance: Amount,
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
            vp_allowlist: vec![],
            tx_allowlist: vec![],
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
            namada_parameters::init_storage(&params, &mut s).unwrap();

            // Tokens
            let token_params = MaspParams {
                max_reward_rate: Dec::from_str("0.1").unwrap(),
                kp_gain_nom: Dec::from_str("0.1").unwrap(),
                kd_gain_nom: Dec::from_str("0.1").unwrap(),
                locked_amount_target: 10_000_u64,
            };

            for (token_addr, (alias, denom)) in tokens() {
                namada_trans_token::write_params(&mut s, &token_addr).unwrap();
                crate::write_params(&token_params, &mut s, &token_addr, &denom)
                    .unwrap();

                write_denom(&mut s, &token_addr, denom).unwrap();

                // Write a minted token balance
                let total_token_balance = initial_balance;
                s.write(&minted_balance_key(&token_addr), total_token_balance)
                    .unwrap();

                // Put the locked ratio into MASP
                s.write(
                    &balance_key(&token_addr, &address::MASP),
                    masp_locked_ratio * total_token_balance,
                )
                .unwrap();

                // Insert tokens into MASP conversion state
                let token_map_key = masp_token_map_key();
                let mut token_map: TokenMap =
                    s.read(&token_map_key).unwrap().unwrap_or_default();
                token_map.insert(alias.to_string(), token_addr.clone());
                s.write(&token_map_key, token_map).unwrap();
            }
        }

        for i in 0..ROUNDS {
            println!("Round {i}");
            update_allowed_conversions(&mut s).unwrap();
            println!();
            println!();
        }
    }

    pub fn tokens() -> HashMap<Address, (&'static str, Denomination)> {
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
