//! PGF lib code.

use namada_core::address::Address;
use namada_parameters::storage as params_storage;
use namada_state::{StorageRead, StorageResult, StorageWrite};
use namada_trans_token::{credit_tokens, get_effective_total_native_supply};

use crate::pgf::storage::{get_parameters, get_payments, get_stewards};
use crate::storage::proposal::{PGFIbcTarget, PGFTarget};

/// Apply the PGF inflation.
pub fn apply_inflation<S, F>(
    storage: &mut S,
    transfer_over_ibc: F,
) -> StorageResult<()>
where
    S: StorageWrite + StorageRead,
    F: Fn(&mut S, &Address, &Address, &PGFIbcTarget) -> StorageResult<()>,
{
    let pgf_parameters = get_parameters(storage)?;
    let staking_token = storage.get_native_token()?;

    let epochs_per_year: u64 = storage
        .read(&params_storage::get_epochs_per_year_key())?
        .expect("Epochs per year should exist in storage");
    let total_supply = get_effective_total_native_supply(storage)?;

    let pgf_inflation_amount = total_supply
        .mul_floor(pgf_parameters.pgf_inflation_rate)?
        .checked_div_u64(epochs_per_year)
        .unwrap_or_default();

    credit_tokens(
        storage,
        &staking_token,
        &super::ADDRESS,
        pgf_inflation_amount,
    )?;

    tracing::info!(
        "Minting {} tokens for PGF rewards distribution into the PGF account \
         (total supply {}).",
        pgf_inflation_amount.to_string_native(),
        total_supply.to_string_native()
    );

    let mut pgf_fundings = get_payments(storage)?;
    // we want to pay first the oldest fundings
    pgf_fundings.sort_by(|a, b| a.id.cmp(&b.id));

    for funding in pgf_fundings {
        let result = match &funding.detail {
            PGFTarget::Internal(target) => namada_trans_token::transfer(
                storage,
                &staking_token,
                &super::ADDRESS,
                &target.target,
                target.amount,
            ),
            PGFTarget::Ibc(target) => transfer_over_ibc(
                storage,
                &staking_token,
                &super::ADDRESS,
                target,
            ),
        };
        match result {
            Ok(()) => {
                tracing::info!(
                    "Paying {} tokens for {} project.",
                    funding.detail.amount().to_string_native(),
                    &funding.detail.target(),
                );
            }
            Err(_) => {
                tracing::warn!(
                    "Failed to pay {} tokens for {} project.",
                    funding.detail.amount().to_string_native(),
                    &funding.detail.target(),
                );
            }
        }
    }

    // Pgf steward inflation
    let stewards = get_stewards(storage)?;
    let pgf_steward_inflation = total_supply
        .mul_floor(pgf_parameters.stewards_inflation_rate)?
        .checked_div_u64(epochs_per_year)
        .unwrap_or_default();

    for steward in stewards {
        for (address, percentage) in steward.reward_distribution {
            let pgf_steward_reward =
                pgf_steward_inflation.mul_floor(percentage)?;

            if credit_tokens(
                storage,
                &staking_token,
                &address,
                pgf_steward_reward,
            )
            .is_ok()
            {
                tracing::info!(
                    "Minting {} tokens for steward {} (total supply {})..",
                    pgf_steward_reward.to_string_native(),
                    address,
                    total_supply.to_string_native()
                );
            } else {
                tracing::warn!(
                    "Failed minting {} tokens for steward {} (total supply \
                     {})..",
                    pgf_steward_reward.to_string_native(),
                    address,
                    total_supply.to_string_native()
                );
            }
        }
    }

    Ok(())
}
