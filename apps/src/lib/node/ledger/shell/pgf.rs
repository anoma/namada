use namada::core::ledger::counsil_treasury::storage as pgf_counsil_treasury_storage;
use namada::core::ledger::pgf::storage as pgf_storage;
use namada::core::ledger::storage_api;
use namada::core::types::token::Amount;
use namada::core::types::transaction::pgf::PgfReceipients;
use namada::ledger::pgf::utils::PgfEvent;
use namada::ledger::pgf_treasury::utils::PgfCounsilTrasuryEvent;
use namada::ledger::storage_api::StorageWrite;
use namada::types::address::InternalAddress;
use namada::types::transaction::counsil_treasury::PgfCounsilMembers;

use super::*;

/// Executing the payments from pgf accounts to the pgf projects
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

    let recipients: PgfReceipients = match shell
        .read_storage_key(&recipients_key)
    {
        Some(recipients) => recipients,
        None => {
            tracing::info!("No countrinous PGF transfer needs to be performed");
            return Ok(());
        }
    };

    // Spending cap
    let spending_cap: Amount = shell
        .read_storage_key(&pgf_storage::get_spending_cap_key())
        .ok_or(Error::BadPGF(
            "Missing spending cap key in storage".to_string(),
        ))?;

    // Spent amount
    let spent_amount_key = pgf_storage::get_spent_amount_key();
    let mut spent_amount: Amount = shell
        .read_storage_key(&spent_amount_key)
        .ok_or(Error::BadPGF(
            "Missing spent amount key in storage".to_string(),
        ))?;

    let native_token = &shell
        .wl_storage
        .get_native_token()
        .expect("Missing native token");

    // Execute payments
    for project in recipients {
        // Spending cap check
        if spent_amount + project.amount > spending_cap {
            tracing::info!(
                "PGF amount of {} for {} exceeds the spending cap of {}",
                project.amount,
                project.address,
                spending_cap
            );
            continue;
        }

        match storage_api::token::transfer(
            &mut shell.wl_storage,
            native_token,
            &Address::Internal(InternalAddress::Pgf),
            &project.address,
            project.amount,
        ) {
            Ok(()) => {
                // Update spent amount
                spent_amount += project.amount;

                let pgf_event: Event =
                    PgfEvent::new(&project.address, &project.amount).into();
                response.events.push(pgf_event);
                tracing::info!(
                    "PGF active transfer with amount {} has been sent to {}.",
                    project.amount,
                    project.address
                );
            }
            Err(msg) => {
                tracing::info!(
                    "PGF active transfer to {}, failed: {}",
                    &project.address,
                    msg
                );

                let pgf_event: Event =
                    PgfEvent::new(&project.address, &0.into()).into();
                response.events.push(pgf_event);
            }
        }
    }

    // Update spent amount
    shell
        .wl_storage
        .write(&spent_amount_key, spent_amount)
        .expect("Should be able to write to storage");

    Ok(())
}

/// Executing the payments to the pgf counsil members
pub fn execute_counsil_rewards<D, H>(
    shell: &mut Shell<D, H>,
    response: &mut shim::response::FinalizeBlock,
) -> Result<()>
where
    D: DB + for<'iter> DBIter<'iter> + Sync + 'static,
    H: StorageHasher + Sync + 'static,
{
    // Read recipients map from storage
    let counsil_members_key =
        pgf_counsil_treasury_storage::get_counsil_members_key();

    let counsil_members: PgfCounsilMembers =
        match shell.read_storage_key(&counsil_members_key) {
            Some(members) => members,
            None => {
                tracing::info!("No PGF counsil members found");
                return Ok(());
            }
        };

    let native_token = &shell
        .wl_storage
        .get_native_token()
        .expect("Missing native token");

    let pgf_counsil_treasury_balance_key = token::balance_key(
        native_token,
        &Address::Internal(InternalAddress::PgfCouncilTreasury),
    );

    let pgf_counsil_treasury_balance: Amount = shell
        .read_storage_key(&pgf_counsil_treasury_balance_key)
        .unwrap_or_default();

    for member in counsil_members {
        let reward_amount = member
            .compute_reward_amount(pgf_counsil_treasury_balance)
            .unwrap_or_default();

        match storage_api::token::transfer(
            &mut shell.wl_storage,
            native_token,
            &Address::Internal(InternalAddress::Pgf),
            &member.address,
            reward_amount,
        ) {
            Ok(()) => {
                let event: Event = PgfCounsilTrasuryEvent::new(
                    &member.address,
                    &reward_amount,
                )
                .into();
                response.events.push(event);
                tracing::info!(
                    "PGF counsil treasury transfer with amount {} has been \
                     sent to {}.",
                    reward_amount,
                    member.address,
                );
            }
            Err(error) => {
                tracing::info!(
                    "PGF counsil treasury transfer to {}, failed: {}",
                    &member.address,
                    error
                );

                let event: Event =
                    PgfCounsilTrasuryEvent::new(&member.address, &0.into())
                        .into();
                response.events.push(event);
            }
        };
    }
    Ok(())
}
