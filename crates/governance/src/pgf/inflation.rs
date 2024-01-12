//! PGF lib code.

use namada_core::types::dec::Dec;
use namada_core::types::token;
use namada_parameters::storage as params_storage;
use namada_storage::{StorageRead, StorageWrite};
use namada_trans_token::credit_tokens;
use namada_trans_token::storage_key::minted_balance_key;

use crate::pgf::storage::{get_parameters, get_payments, get_stewards};

/// Apply the PGF inflation.
pub fn apply_inflation<S>(storage: &mut S) -> namada_storage::Result<()>
where
    S: StorageRead + StorageWrite,
{
    let pgf_parameters = get_parameters(storage)?;
    let staking_token = storage.get_native_token()?;

    let epochs_per_year: u64 = storage
        .read(&params_storage::get_epochs_per_year_key())?
        .expect("Epochs per year should exist in storage");
    let total_tokens: token::Amount = storage
        .read(&minted_balance_key(&staking_token))?
        .expect("Total NAM balance should exist in storage");

    let pgf_pd_rate =
        pgf_parameters.pgf_inflation_rate / Dec::from(epochs_per_year);
    let pgf_inflation = Dec::from(total_tokens) * pgf_pd_rate;
    let pgf_inflation_amount = token::Amount::from(pgf_inflation);

    credit_tokens(
        storage,
        &staking_token,
        &super::ADDRESS,
        pgf_inflation_amount,
    )?;

    tracing::info!(
        "Minting {} tokens for PGF rewards distribution into the PGF account.",
        pgf_inflation_amount.to_string_native()
    );

    let mut pgf_fundings = get_payments(storage)?;
    // we want to pay first the oldest fundings
    pgf_fundings.sort_by(|a, b| a.id.cmp(&b.id));

    for funding in pgf_fundings {
        if namada_trans_token::transfer(
            storage,
            &staking_token,
            &super::ADDRESS,
            &funding.detail.target,
            funding.detail.amount,
        )
        .is_ok()
        {
            tracing::info!(
                "Paying {} tokens for {} project.",
                funding.detail.amount.to_string_native(),
                &funding.detail.target,
            );
        } else {
            tracing::warn!(
                "Failed to pay {} tokens for {} project.",
                funding.detail.amount.to_string_native(),
                &funding.detail.target,
            );
        }
    }

    // Pgf steward inflation
    let stewards = get_stewards(storage)?;
    let pgf_stewards_pd_rate =
        pgf_parameters.stewards_inflation_rate / Dec::from(epochs_per_year);
    let pgf_steward_inflation = Dec::from(total_tokens) * pgf_stewards_pd_rate;

    for steward in stewards {
        for (address, percentage) in steward.reward_distribution {
            let pgf_steward_reward = pgf_steward_inflation
                .checked_mul(&percentage)
                .unwrap_or_default();
            let reward_amount = token::Amount::from(pgf_steward_reward);

            if credit_tokens(storage, &staking_token, &address, reward_amount)
                .is_ok()
            {
                tracing::info!(
                    "Minting {} tokens for steward {}.",
                    reward_amount.to_string_native(),
                    address,
                );
            } else {
                tracing::warn!(
                    "Failed minting {} tokens for steward {}.",
                    reward_amount.to_string_native(),
                    address,
                );
            }
        }
    }

    Ok(())
}
