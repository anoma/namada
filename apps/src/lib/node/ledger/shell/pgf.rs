use std::collections::BTreeSet;

use namada::core::ledger::governance::storage::proposal::PGFTarget;
use namada::core::ledger::pgf::storage::keys as pgf_keys;
use namada::core::ledger::pgf::ADDRESS as pgf_address;
use namada::ledger::pgf::utils::ProposalEvent as PgfProposalEvent;
use namada::ledger::storage::{DBIter, StorageHasher, DB};
use namada::ledger::storage_api::token;

use super::utils::force_read;
use super::{Shell, *};
use crate::node::ledger::shims::abcipp_shim_types::shim;

pub fn execute_pgf_payments<D, H>(
    shell: &mut Shell<D, H>,
    response: &mut shim::response::FinalizeBlock,
) -> Result<()>
where
    D: DB + for<'iter> DBIter<'iter> + Sync + 'static,
    H: StorageHasher + Sync + 'static,
{
    let pgf_payments_key = pgf_keys::get_payments_key();
    let pgf_payments: BTreeSet<PGFTarget> =
        force_read(&shell.wl_storage, &pgf_payments_key)?;

    let native_token = &shell.wl_storage.get_native_token()?;

    for payment in pgf_payments {
        let success = token::transfer(
            &mut shell.wl_storage,
            native_token,
            &pgf_address,
            &payment.target,
            payment.amount,
        )
        .is_ok();
        let proposal_event = PgfProposalEvent::pgf_funding_payment(
            payment.target.clone(),
            payment.amount,
            success,
        )
        .into();
        response.events.push(proposal_event);

        tracing::info!(
            "Pgf funding payment of {}nam toward {} was {}",
            payment.amount,
            payment.target,
            if success { "successful" } else { "rejected" }
        );
    }

    Ok(())
}
