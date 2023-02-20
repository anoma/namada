use super::*;
use namada::core::ledger::storage_api::token;
use namada::ledger::pgf::utils::PgfEvent;
use namada::core::types::token::Amount;
use namada::core::ledger::pgf::storage as pgf_storage;
use namada::core::types::transaction::pgf::PgfProjectsUpdate;
use namada::core::types::address;
use namada::ledger::storage_api::StorageWrite;
use namada::types::address::InternalAddress;

pub fn execute_active_pgf_funding<D, H>(
    shell: &mut Shell<D, H>,
    response: &mut shim::response::FinalizeBlock,
) -> Result<()>
where
    D: DB + for<'iter> DBIter<'iter> + Sync + 'static,
    H: StorageHasher + Sync + 'static,
{
    // Read recipients map from storage
    let recipients_key = pgf_storage::get_cpgf_recipient_key();

    let recipients: PgfProjectsUpdate = match shell.read_storage_key(&recipients_key) {
        Some(r) => r,
        None => {
            tracing::info!("No PGF active payment needs to be performed");
            return Ok(());
        }
    };

    // Spending cap
    let spending_cap: Amount = shell.read_storage_key(&pgf_storage::get_spending_cap_key()).ok_or(Error::BadPGF("Missing spending cap key in storage".to_string()))?;

    // Spent amount
    let spent_amount_key = pgf_storage::get_spent_amount_key();
    let mut spent_amount: Amount = shell.read_storage_key(&spent_amount_key).ok_or(Error::BadPGF("Missing spent amount key in storage".to_string()))?;

    let native_token = &shell.wl_storage.get_native_token().expect("Missing native token");

    // Execute payments
    for project in recipients {
        // Spending cap check
        if spent_amount + project.amount > spending_cap {
            tracing::info!("PGF amount of {} for {} exceeds the spending cap of {}", project.amount, project.address, spending_cap);
            continue;
        }

        match token::transfer(&mut shell.wl_storage, native_token, &Address::Internal(InternalAddress::Pgf), &project.address, project.amount) {
            Ok(()) => {
                // Update spent amount
                spent_amount += project.amount;

                let pgf_event: Event = PgfEvent::new(
                    &project.address,
                    &project.amount
                )
                .into();
                response.events.push(pgf_event);
                tracing::info!("PGF active transfer with amount {} has been sent to {}.", project.address, project.amount);
            },
            Err(msg) => {
                tracing::info!("PGF active transfer to {}, failed: {}", &project.address, msg);

                let pgf_event: Event = PgfEvent::new(
                    &project.address,
                    &0.into()
                )
                .into();
                response.events.push(pgf_event);
            }
        }
    }

    // Update spent amount
    shell.wl_storage.write(&spent_amount_key, spent_amount).expect("Should be able to write to storage");

Ok(())
}