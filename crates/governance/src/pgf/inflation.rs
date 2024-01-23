//! PGF lib code.

use namada_core::types::address::Address;

use namada_core::types::token;
use namada_parameters::storage as params_storage;
use namada_state::{
    DBIter, StorageHasher, StorageRead, StorageResult, WlStorage, DB,
};
use namada_trans_token::credit_tokens;
use namada_trans_token::storage_key::minted_balance_key;

use crate::pgf::storage::{get_parameters, get_payments, get_stewards};
use crate::storage::proposal::{PGFIbcTarget, PGFTarget};

/// Apply the PGF inflation.
pub fn apply_inflation<D, H, F>(
    storage: &mut WlStorage<D, H>,
    transfer_over_ibc: F,
) -> StorageResult<()>
where
    D: DB + for<'iter> DBIter<'iter> + Sync + 'static,
    H: StorageHasher + Sync + 'static,
    F: Fn(
        &mut WlStorage<D, H>,
        &Address,
        &Address,
        &PGFIbcTarget,
    ) -> StorageResult<()>,
{
    let pgf_parameters = get_parameters(storage)?;
    let staking_token = storage.get_native_token()?;

    let epochs_per_year: u64 = storage
        .read(&params_storage::get_epochs_per_year_key())?
        .expect("Epochs per year should exist in storage");
    let total_tokens: token::Amount = storage
        .read(&minted_balance_key(&staking_token))?
        .expect("Total native token balance should exist in storage"); // 116400000

    let pgf_inflation_amount = (total_tokens
        .mul_ceil(pgf_parameters.pgf_inflation_rate))
        / epochs_per_year;

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
        total_tokens.to_string_native()
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
    let pgf_steward_inflation = (total_tokens
        .mul_ceil(pgf_parameters.stewards_inflation_rate))
        / epochs_per_year;

    for steward in stewards {
        for (address, percentage) in steward.reward_distribution {
            let pgf_steward_reward = pgf_steward_inflation.mul_ceil(percentage);
            let reward_amount = pgf_steward_reward;

            if credit_tokens(storage, &staking_token, &address, reward_amount)
                .is_ok()
            {
                tracing::info!(
                    "Minting {} tokens for steward {} (total supply {})..",
                    reward_amount.to_string_native(),
                    address,
                    total_tokens.to_string_native()
                );
            } else {
                tracing::warn!(
                    "Failed minting {} tokens for steward {} (total supply \
                     {})..",
                    reward_amount.to_string_native(),
                    address,
                    total_tokens.to_string_native()
                );
            }
        }
    }

    Ok(())
}
