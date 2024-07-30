//! MASP rewards conversions

use namada_controller::PDController;
use namada_core::address::{Address, MASP};
use namada_core::arith::checked;
#[cfg(any(feature = "multicore", test))]
use namada_core::borsh::BorshSerializeExt;
use namada_core::dec::Dec;
#[cfg(any(feature = "multicore", test))]
use namada_core::hash::Hash;
use namada_core::token::{Amount, DenominatedAmount, Denomination};
use namada_core::uint::Uint;
use namada_storage::{StorageRead, StorageWrite};
use namada_systems::{parameters, trans_token};

#[cfg(any(feature = "multicore", test))]
use crate::storage_key::{masp_assets_hash_key, masp_token_map_key};
use crate::storage_key::{
    masp_kd_gain_key, masp_kp_gain_key, masp_last_inflation_key,
    masp_last_locked_amount_key, masp_locked_amount_target_key,
    masp_max_reward_rate_key,
};
use crate::WithConversionState;

/// Compute shielded token inflation amount
#[allow(clippy::too_many_arguments)]
pub fn compute_inflation(
    locked_amount: Uint,
    total_native_amount: Uint,
    max_reward_rate: Dec,
    last_inflation_amount: Uint,
    p_gain_nom: Dec,
    d_gain_nom: Dec,
    epochs_per_year: u64,
    target_amount: Dec,
    last_amount: Dec,
) -> Uint {
    let controller = PDController::new(
        total_native_amount,
        max_reward_rate,
        last_inflation_amount,
        p_gain_nom,
        d_gain_nom,
        epochs_per_year,
        target_amount,
        last_amount,
    );

    let metric = Dec::try_from(locked_amount)
        .expect("Should not fail to convert Uint to Dec");
    let control_coeff = max_reward_rate
        .checked_div(controller.get_epochs_per_year())
        .expect("Control coefficient overflow");

    tracing::debug!(
        "Shielded token inflation inputs: {controller:#?}, metric: {metric}, \
         coefficient: {control_coeff}"
    );
    controller
        .compute_inflation(control_coeff, metric)
        .expect("Inflation calculation overflow")
}

/// Compute the precision of MASP rewards for the given token. This function
/// must be a non-zero constant for a given token.
pub fn calculate_masp_rewards_precision<S, TransToken>(
    storage: &mut S,
    addr: &Address,
) -> namada_storage::Result<(u128, Denomination)>
where
    S: StorageWrite + StorageRead,
    TransToken: trans_token::Read<S>,
{
    let denomination = TransToken::read_denom(storage, addr)?
        .expect("failed to read token denomination");
    // Inflation is implicitly denominated by this value. The lower this
    // figure, the less precise inflation computations are. This is especially
    // problematic when inflation is coming from a token with much higher
    // denomination than the native token. The higher this figure, the higher
    // the threshold of holdings required in order to receive non-zero rewards.
    // This value should be fixed constant for each asset type. Here we choose
    // a thousandth of the given asset.
    let precision_denom = std::cmp::max(u32::from(denomination.0), 3)
        .checked_sub(3)
        .expect("Cannot underflow");
    Ok((checked!(10u128 ^ precision_denom)?, denomination))
}

/// Compute the MASP rewards by applying the PD-controller to the genesis
/// parameters and the last inflation and last locked rewards ratio values.
pub fn calculate_masp_rewards<S, TransToken>(
    storage: &mut S,
    token: &Address,
    masp_epochs_per_year: u64,
) -> namada_storage::Result<((u128, u128), Denomination)>
where
    S: StorageWrite + StorageRead,
    TransToken: trans_token::Keys + trans_token::Read<S>,
{
    let (precision, denomination) =
        calculate_masp_rewards_precision::<S, TransToken>(storage, token)?;

    let masp_addr = MASP;

    // Query the storage for information -------------------------

    //// information about the amount of native tokens on the chain
    let total_native_tokens =
        TransToken::get_effective_total_native_supply(storage)?;

    // total locked amount in the Shielded pool
    let total_tokens_in_masp =
        TransToken::read_balance(storage, token, &masp_addr)?;

    //// Values from the last epoch
    let last_inflation: Amount = storage
        .read(&masp_last_inflation_key::<TransToken>(token))?
        .expect("failure to read last inflation");

    let last_locked_amount: Amount = storage
        .read(&masp_last_locked_amount_key::<TransToken>(token))?
        .expect("failure to read last inflation");

    //// Parameters for each token
    let max_reward_rate: Dec = storage
        .read(&masp_max_reward_rate_key::<TransToken>(token))?
        .expect("max reward should properly decode");

    let kp_gain_nom: Dec = storage
        .read(&masp_kp_gain_key::<TransToken>(token))?
        .expect("kp_gain_nom reward should properly decode");

    let kd_gain_nom: Dec = storage
        .read(&masp_kd_gain_key::<TransToken>(token))?
        .expect("kd_gain_nom reward should properly decode");

    let target_locked_amount: Amount = storage
        .read(&masp_locked_amount_target_key::<TransToken>(token))?
        .expect("locked ratio target should properly decode");

    let target_locked_dec = Dec::try_from(target_locked_amount.raw_amount())
        .expect("Should not fail to convert Uint to Dec");
    let last_locked_dec = Dec::try_from(last_locked_amount.raw_amount())
        .expect("Should not fail to convert Uint to Dec");

    // Initial computation of the new shielded inflation
    let inflation = compute_inflation(
        total_tokens_in_masp.raw_amount(),
        total_native_tokens.raw_amount(),
        max_reward_rate,
        last_inflation.raw_amount(),
        kp_gain_nom,
        kd_gain_nom,
        masp_epochs_per_year,
        target_locked_dec,
        last_locked_dec,
    );

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
        checked!(
            total_tokens_in_masp.raw_amount() / precision.into()
                * Uint::from(noterized_inflation)
        )?,
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
        masp_epochs_per_year,
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
    storage.write(
        &masp_last_inflation_key::<TransToken>(token),
        inflation_amount,
    )?;

    storage.write(
        &masp_last_locked_amount_key::<TransToken>(token),
        total_tokens_in_masp,
    )?;

    Ok(((noterized_inflation, precision), denomination))
}

// This is only enabled when "wasm-runtime" is on, because we're using rayon
#[cfg(not(any(feature = "multicore", test)))]
/// Update the MASP's allowed conversions
pub fn update_allowed_conversions<S, Params, TransToken>(
    _storage: &mut S,
) -> namada_storage::Result<()>
where
    S: StorageWrite + StorageRead + WithConversionState,
    Params: parameters::Read<S>,
    TransToken: trans_token::Keys,
{
    Ok(())
}

#[cfg(any(feature = "multicore", test))]
/// Update the MASP's allowed conversions
pub fn update_allowed_conversions<S, Params, TransToken>(
    storage: &mut S,
) -> namada_storage::Result<()>
where
    S: StorageWrite + StorageRead + WithConversionState,
    Params: parameters::Read<S>,
    TransToken:
        trans_token::Keys + trans_token::Read<S> + trans_token::Write<S>,
{
    use std::cmp::Ordering;
    use std::collections::BTreeMap;

    use masp_primitives::bls12_381;
    use masp_primitives::convert::AllowedConversion;
    use masp_primitives::ff::PrimeField;
    use masp_primitives::merkle_tree::FrozenCommitmentTree;
    use masp_primitives::sapling::Node;
    use masp_primitives::transaction::components::I128Sum as MaspAmount;
    use namada_core::arith::CheckedAdd;
    use namada_core::masp::{encode_asset_type, MaspEpoch};
    use namada_core::token::{MaspDigitPos, NATIVE_MAX_DECIMAL_PLACES};
    use namada_storage::conversion_state::ConversionLeaf;
    use namada_storage::{Error, OptionExt, ResultExt};
    use rayon::iter::{
        IndexedParallelIterator, IntoParallelIterator, ParallelIterator,
    };
    use rayon::prelude::ParallelSlice;

    use crate::mint_rewards;

    // The derived conversions will be placed in MASP address space
    let masp_addr = MASP;

    let token_map_key = masp_token_map_key();
    let token_map: namada_core::masp::TokenMap =
        storage.read(&token_map_key)?.unwrap_or_default();
    let mut masp_reward_keys: Vec<_> = token_map.values().cloned().collect();
    let mut masp_reward_denoms = BTreeMap::new();
    // Put the native rewards first because other inflation computations depend
    // on it
    let native_token = storage.get_native_token()?;
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
    let mut total_reward = Amount::zero();

    // Construct MASP asset type for rewards. Always deflate and timestamp
    // reward tokens with the zeroth epoch to minimize the number of convert
    // notes clients have to use. This trick works under the assumption that
    // reward tokens will then be reinflated back to the current epoch.
    let reward_assets = [
        encode_asset_type(
            native_token.clone(),
            NATIVE_MAX_DECIMAL_PLACES.into(),
            MaspDigitPos::Zero,
            Some(MaspEpoch::zero()),
        )
        .into_storage_result()?,
        encode_asset_type(
            native_token.clone(),
            NATIVE_MAX_DECIMAL_PLACES.into(),
            MaspDigitPos::One,
            Some(MaspEpoch::zero()),
        )
        .into_storage_result()?,
        encode_asset_type(
            native_token.clone(),
            NATIVE_MAX_DECIMAL_PLACES.into(),
            MaspDigitPos::Two,
            Some(MaspEpoch::zero()),
        )
        .into_storage_result()?,
        encode_asset_type(
            native_token.clone(),
            NATIVE_MAX_DECIMAL_PLACES.into(),
            MaspDigitPos::Three,
            Some(MaspEpoch::zero()),
        )
        .into_storage_result()?,
    ];
    // Conversions from the previous to current asset for each address
    let mut current_convs = BTreeMap::<
        (Address, Denomination, MaspDigitPos),
        AllowedConversion,
    >::new();
    // Native token inflation values are always with respect to this
    let ref_inflation = calculate_masp_rewards_precision::<S, TransToken>(
        storage,
        &native_token,
    )?
    .0;

    // Reward all tokens according to above reward rates
    let masp_epoch_multiplier = Params::masp_epoch_multiplier(storage)?;
    let masp_epoch = MaspEpoch::try_from_epoch(
        storage.get_block_epoch()?,
        masp_epoch_multiplier,
    )
    .map_err(namada_storage::Error::new_const)?;
    let prev_masp_epoch = match masp_epoch.prev() {
        Some(epoch) => epoch,
        None => return Ok(()),
    };
    let epochs_per_year = Params::epochs_per_year(storage)?;
    let masp_epochs_per_year =
        checked!(epochs_per_year / masp_epoch_multiplier)?;
    for token in &masp_reward_keys {
        let ((reward, precision), denom) =
            calculate_masp_rewards::<S, TransToken>(
                storage,
                token,
                masp_epochs_per_year,
            )?;
        masp_reward_denoms.insert(token.clone(), denom);
        // Dispense a transparent reward in parallel to the shielded rewards
        let addr_bal = TransToken::read_balance(storage, token, &masp_addr)?;

        // Get the last rewarded amount of the native token
        let normed_inflation = *storage
            .conversion_state_mut()
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
                Some(prev_masp_epoch),
            )
            .into_storage_result()?;
            let new_asset = encode_asset_type(
                token.clone(),
                denom,
                digit,
                Some(masp_epoch),
            )
            .into_storage_result()?;
            if *token == native_token {
                // The amount that will be given of the new native token for
                // every amount of the native token given in the
                // previous epoch
                let inflation_uint = Uint::from(normed_inflation);
                let reward = Uint::from(reward);
                let precision = Uint::from(precision);
                let new_normed_inflation = checked!(
                    inflation_uint + (inflation_uint * reward) / precision
                )?;
                let new_normed_inflation = u128::try_from(new_normed_inflation)
                    .unwrap_or_else(|_| {
                        tracing::warn!(
                            "MASP inflation for the native token {} is kept \
                             the same as in the last epoch because the \
                             computed value is too large. Please check the \
                             inflation parameters.",
                            token
                        );
                        normed_inflation
                    });
                // The conversion is computed such that if consecutive
                // conversions are added together, the
                // intermediate native tokens cancel/
                // telescope out
                let cur_conv = MaspAmount::from_pair(
                    old_asset,
                    i128::try_from(normed_inflation)
                        .ok()
                        .and_then(i128::checked_neg)
                        .ok_or_err_msg("Current inflation overflow")?,
                );
                let new_conv = MaspAmount::from_pair(
                    new_asset,
                    i128::try_from(new_normed_inflation)
                        .into_storage_result()?,
                );
                current_convs.insert(
                    (token.clone(), denom, digit),
                    checked!(cur_conv + &new_conv)?.into(),
                );
                // Operations that happen exactly once for each token
                if digit == MaspDigitPos::Three {
                    // The reward for each reward.1 units of the current asset
                    // is reward.0 units of the reward token
                    let native_reward = addr_bal
                        .u128_eucl_div_rem((
                            new_normed_inflation,
                            normed_inflation,
                        ))
                        .ok_or_else(|| {
                            Error::new_const("Three digit reward overflow")
                        })?;
                    total_reward = total_reward
                        .checked_add(
                            native_reward
                                .0
                                .checked_add(native_reward.1)
                                .unwrap_or(Amount::max())
                                .checked_sub(addr_bal)
                                .unwrap_or_default(),
                        )
                        .ok_or_else(|| {
                            Error::new_const(
                                "Three digit total reward overflow",
                            )
                        })?;
                    // Save the new normed inflation

                    let _ = storage
                        .conversion_state_mut()
                        .normed_inflation
                        .insert(new_normed_inflation);
                }
            } else {
                // Express the inflation reward in real terms, that is, with
                // respect to the native asset in the zeroth
                // epoch
                let reward_uint = Uint::from(reward);
                let ref_inflation_uint = Uint::from(ref_inflation);
                let inflation_uint = Uint::from(normed_inflation);
                let real_reward = checked!(
                    (reward_uint * ref_inflation_uint) / inflation_uint
                )?
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
                let precision_i128 =
                    i128::try_from(precision).into_storage_result()?;
                let real_reward_i128 =
                    i128::try_from(real_reward).into_storage_result()?;
                current_convs.insert(
                    (token.clone(), denom, digit),
                    checked!(
                        MaspAmount::from_pair(old_asset, -precision_i128)
                            + &MaspAmount::from_pair(new_asset, precision_i128)
                            + &MaspAmount::from_pair(
                                reward_assets[digit as usize],
                                real_reward_i128,
                            )
                    )?
                    .into(),
                );
                // Operations that happen exactly once for each token
                if digit == MaspDigitPos::Three {
                    // The reward for each reward.1 units of the current asset
                    // is reward.0 units of the reward token
                    total_reward = total_reward
                        .checked_add(
                            addr_bal
                                .u128_eucl_div_rem((reward, precision))
                                .ok_or_else(|| {
                                    Error::new_const(
                                        "Total reward calculation overflow",
                                    )
                                })?
                                .0,
                        )
                        .ok_or_else(|| {
                            Error::new_const("Total reward overflow")
                        })?;
                }
            }
            // Add a conversion from the previous asset type
            storage.conversion_state_mut().assets.insert(
                old_asset,
                ConversionLeaf {
                    token: token.clone(),
                    denom,
                    digit_pos: digit,
                    epoch: prev_masp_epoch,
                    conversion: MaspAmount::zero().into(),
                    leaf_pos: 0,
                },
            );
        }
    }

    // Try to distribute Merkle leaf updating as evenly as possible across
    // multiple cores
    let num_threads = rayon::current_num_threads();
    // Put assets into vector to enable computation batching
    let assets: Vec<_> = storage
        .conversion_state_mut()
        .assets
        .values_mut()
        .enumerate()
        .collect();
    // ceil(assets.len() / num_threads)

    #[allow(clippy::arithmetic_side_effects)]
    let notes_per_thread_max = (assets.len() + num_threads - 1) / num_threads;
    // floor(assets.len() / num_threads)
    #[allow(clippy::arithmetic_side_effects)]
    let notes_per_thread_min = assets.len() / num_threads;

    // Now on each core, add the latest conversion to each conversion
    let conv_notes: Vec<Node> = assets
        .into_par_iter()
        .with_min_len(notes_per_thread_min)
        .with_max_len(notes_per_thread_max)
        .map(|(idx, leaf)| {
            // Try to get the applicable conversion delta
            let cur_conv_key = (leaf.token.clone(), leaf.denom, leaf.digit_pos);
            if let Some(current_conv) = current_convs.get(&cur_conv_key) {
                // Use transitivity to update conversion
                #[allow(clippy::arithmetic_side_effects)]
                {
                    leaf.conversion += current_conv.clone();
                }
            }
            // Update conversion position to leaf we are about to create
            leaf.leaf_pos = idx;
            // The merkle tree need only provide the conversion commitment,
            // the remaining information is provided through the storage API
            Node::new(leaf.conversion.cmu().to_repr())
        })
        .collect();

    // Update the MASP's transparent reward token balance to ensure that it
    // is sufficiently backed to redeem rewards
    mint_rewards::<S, TransToken>(storage, total_reward)?;

    // Try to distribute Merkle tree construction as evenly as possible
    // across multiple cores
    // Merkle trees must have exactly 2^n leaves to be mergeable
    let mut notes_per_thread_rounded = 1;

    // Cannot overflow
    #[allow(clippy::arithmetic_side_effects)]
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
    storage.conversion_state_mut().tree =
        FrozenCommitmentTree::merge(&tree_parts);
    // Update the anchor in storage
    storage.write(
        &crate::storage_key::masp_convert_anchor_key(),
        namada_core::hash::Hash(
            bls12_381::Scalar::from(storage.conversion_state().tree.root())
                .to_bytes(),
        ),
    )?;

    if !masp_reward_keys.contains(&native_token) {
        // Since MASP rewards are denominated in NAM tokens, ensure that clients
        // are able to decode them.
        masp_reward_denoms
            .insert(native_token.clone(), NATIVE_MAX_DECIMAL_PLACES.into());
    }
    // Add purely decoding entries to the assets map. These will be
    // overwritten before the creation of the next commitment tree
    for (addr, denom) in masp_reward_denoms {
        for digit in MaspDigitPos::iter() {
            // Add the decoding entry for the new asset type. An uncommitted
            // node position is used since this is not a conversion.
            let new_asset =
                encode_asset_type(addr.clone(), denom, digit, Some(masp_epoch))
                    .into_storage_result()?;
            let tree_size = storage.conversion_state().tree.size();
            storage.conversion_state_mut().assets.insert(
                new_asset,
                ConversionLeaf {
                    token: addr.clone(),
                    denom,
                    digit_pos: digit,
                    epoch: masp_epoch,
                    conversion: MaspAmount::zero().into(),
                    leaf_pos: tree_size,
                },
            );
        }
    }
    // store only the assets hash because the size is quite large
    let assets_hash =
        Hash::sha256(storage.conversion_state().assets.serialize_to_vec());
    storage.write(&masp_assets_hash_key(), assets_hash)?;

    Ok(())
}

#[allow(clippy::arithmetic_side_effects)]
#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use namada_core::address;
    use namada_core::collections::HashMap;
    use namada_core::dec::testing::arb_non_negative_dec;
    use namada_core::token::testing::arb_amount;
    use namada_storage::testing::TestStorage;
    use namada_trans_token::storage_key::{balance_key, minted_balance_key};
    use namada_trans_token::write_denom;
    use proptest::prelude::*;
    use proptest::test_runner::Config;
    use test_log::test;

    use super::*;
    use crate::ShieldedParams;

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

        let mut s = TestStorage::default();
        // Initialize the state
        {
            // Parameters
            namada_parameters::init_test_storage(&mut s).unwrap();

            // Tokens
            let token_params = ShieldedParams {
                max_reward_rate: Dec::from_str("0.1").unwrap(),
                kp_gain_nom: Dec::from_str("0.1").unwrap(),
                kd_gain_nom: Dec::from_str("0.1").unwrap(),
                locked_amount_target: 10_000_u64,
            };

            for (token_addr, (alias, denom)) in tokens() {
                namada_trans_token::write_params(&mut s, &token_addr).unwrap();
                crate::write_params::<_, namada_trans_token::Store<()>>(
                    &token_params,
                    &mut s,
                    &token_addr,
                    &denom,
                )
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
                let mut token_map: namada_core::masp::TokenMap =
                    s.read(&token_map_key).unwrap().unwrap_or_default();
                token_map.insert(alias.to_string(), token_addr.clone());
                s.write(&token_map_key, token_map).unwrap();
            }
        }

        for i in 0..ROUNDS {
            println!("Round {i}");
            update_allowed_conversions::<
                _,
                namada_parameters::Store<_>,
                namada_trans_token::Store<_>,
            >(&mut s)
            .unwrap();
            println!();
            println!();
        }
    }

    pub fn tokens() -> HashMap<Address, (&'static str, Denomination)> {
        vec![
            (address::testing::nam(), ("nam", 6.into())),
            (address::testing::btc(), ("btc", 8.into())),
            (address::testing::eth(), ("eth", 18.into())),
            (address::testing::dot(), ("dot", 10.into())),
            (address::testing::schnitzel(), ("schnitzel", 6.into())),
            (address::testing::apfel(), ("apfel", 6.into())),
            (address::testing::kartoffel(), ("kartoffel", 6.into())),
        ]
        .into_iter()
        .collect()
    }

    #[test]
    fn test_masp_inflation_playground() {
        let denom = Uint::from(1_000_000); // token denomination (usually 6)
        let total_tokens = 10_000_000_000_u64; // 10B naan
        let mut total_tokens = Uint::from(total_tokens) * denom;
        let locked_tokens_target = Uint::from(500_000) * denom; // Dependent on the token type
        let init_locked_ratio = Dec::from_str("0.1").unwrap(); // Arbitrary amount to play around with
        let init_locked_tokens = (init_locked_ratio
            * Dec::try_from(locked_tokens_target).unwrap())
        .to_uint()
        .unwrap();
        let epochs_per_year = 730_u64; // SE configuration
        let max_reward_rate = Dec::from_str("0.01").unwrap(); // Pre-determined based on token type
        let mut last_inflation_amount = Uint::zero();
        let p_gain_nom = Dec::from_str("25000").unwrap(); // To be configured
        let d_gain_nom = Dec::from_str("25000").unwrap(); // To be configured

        let mut locked_amount = init_locked_tokens;
        let mut locked_tokens_last = init_locked_tokens;

        let num_rounds = 10;
        println!();

        for round in 0..num_rounds {
            let inflation = compute_inflation(
                locked_amount,
                total_tokens,
                max_reward_rate,
                last_inflation_amount,
                p_gain_nom,
                d_gain_nom,
                epochs_per_year,
                Dec::try_from(locked_tokens_target).unwrap(),
                Dec::try_from(locked_tokens_last).unwrap(),
            );

            let rate = Dec::try_from(inflation).unwrap()
                * Dec::from(epochs_per_year)
                / Dec::try_from(total_tokens).unwrap();

            println!(
                "Round {round}: Locked amount: {locked_amount}, inflation \
                 rate: {rate} -- (raw infl: {inflation})",
            );
            // dbg!(&controller);

            last_inflation_amount = inflation;
            total_tokens += inflation;
            locked_tokens_last = locked_amount;

            let change_staked_tokens = Uint::from(2) * locked_tokens_target;
            locked_amount += change_staked_tokens;
        }
    }
}
