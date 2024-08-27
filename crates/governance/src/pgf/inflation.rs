//! PGF lib code.

use namada_core::address::Address;
use namada_state::{Result, StorageRead, StorageWrite};
use namada_systems::{parameters, trans_token};

use crate::pgf::storage::{
    get_continuous_pgf_payments, get_parameters, get_stewards,
};
use crate::storage::proposal::{PGFIbcTarget, PGFTarget};

/// Apply the PGF inflation.
pub fn apply_inflation<S, Params, TransToken, F>(
    storage: &mut S,
    transfer_over_ibc: F,
) -> Result<()>
where
    S: StorageWrite + StorageRead,
    Params: parameters::Read<S>,
    TransToken: trans_token::Read<S> + trans_token::Write<S>,
    F: Fn(&mut S, &Address, &Address, &PGFIbcTarget) -> Result<()>,
{
    let pgf_parameters = get_parameters(storage)?;
    let staking_token = storage.get_native_token()?;

    let epochs_per_year = Params::epochs_per_year(storage)?;
    let total_supply = TransToken::get_effective_total_native_supply(storage)?;

    let pgf_inflation_amount = total_supply
        .mul_floor(pgf_parameters.pgf_inflation_rate)?
        .checked_div_u64(epochs_per_year)
        .unwrap_or_default();

    TransToken::credit_tokens(
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

    let mut pgf_fundings = get_continuous_pgf_payments(storage)?;
    // prioritize the payments by oldest gov proposal ID
    pgf_fundings.sort_by(|a, b| a.id.cmp(&b.id));

    for funding in pgf_fundings {
        let result = match &funding.detail {
            PGFTarget::Internal(target) => TransToken::transfer(
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

    // PGF steward inflation
    let stewards = get_stewards(storage)?;
    let pgf_steward_inflation = total_supply
        .mul_floor(pgf_parameters.stewards_inflation_rate)?
        .checked_div_u64(epochs_per_year)
        .unwrap_or_default();

    for steward in stewards {
        for (address, percentage) in steward.reward_distribution {
            let pgf_steward_reward =
                pgf_steward_inflation.mul_floor(percentage)?;

            if TransToken::credit_tokens(
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
