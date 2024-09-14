//! Token transaction

use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};

use namada_core::collections::HashSet;
use namada_core::masp;
use namada_events::{EmitEvents, EventLevel};
use namada_shielded_token::{utils, MaspTxId};
use namada_storage::{Error, OptionExt, ResultExt};
use namada_trans_token::event::{TokenEvent, TokenOperation};
pub use namada_trans_token::tx::transfer;
use namada_trans_token::UserAccount;
use namada_tx::action::{self, Action, MaspAction};
use namada_tx::BatchedTx;
use namada_tx_env::{Address, Result, TxEnv};

use crate::{Transfer, TransparentTransfersRef};

/// Transparent and shielded token transfers that can be used in a transaction.
pub fn multi_transfer<ENV>(
    env: &mut ENV,
    transfers: Transfer,
    tx_data: &BatchedTx,
    event_desc: Cow<'static, str>,
) -> Result<()>
where
    ENV: TxEnv + EmitEvents + action::Write<Err = Error>,
{
    // Effect the transparent multi transfer(s)
    let debited_accounts =
        if let Some(transparent) = transfers.transparent_part() {
            apply_transparent_transfers(env, transparent, event_desc)
                .wrap_err("Transparent token transfer failed")?
        } else {
            HashSet::new()
        };

    // Apply the shielded transfer if there is a link to one
    if let Some(masp_section_ref) = transfers.shielded_section_hash {
        apply_shielded_transfer(
            env,
            masp_section_ref,
            debited_accounts,
            tx_data,
        )
        .wrap_err("Shielded token transfer failed")?;
    }
    Ok(())
}

/// Transfer tokens from `sources` to `targets` and submit a transfer event.
///
/// Returns an `Err` if any source has insufficient balance or if the transfer
/// to any destination would overflow (This can only happen if the total supply
/// doesn't fit in `token::Amount`). Returns a set of debited accounts.
pub fn apply_transparent_transfers<ENV>(
    env: &mut ENV,
    transfers: TransparentTransfersRef<'_>,
    event_desc: Cow<'static, str>,
) -> Result<HashSet<Address>>
where
    ENV: TxEnv + EmitEvents,
{
    let sources = transfers.sources();
    let targets = transfers.targets();
    let debited_accounts =
        namada_trans_token::multi_transfer(env, &sources, &targets)?;

    let mut evt_sources = BTreeMap::new();
    let mut evt_targets = BTreeMap::new();
    let mut post_balances = BTreeMap::new();

    for ((src, token), amount) in sources {
        // The tx must be authorized by the source address
        env.insert_verifier(&src)?;
        if token.is_internal() {
            // Established address tokens do not have VPs themselves, their
            // validation is handled by the `Multitoken` internal address,
            // but internal token addresses have to verify
            // the transfer
            env.insert_verifier(&token)?;
        }
        evt_sources.insert(
            (UserAccount::Internal(src.clone()), token.clone()),
            amount.into(),
        );
        post_balances.insert(
            (UserAccount::Internal(src.clone()), token.clone()),
            crate::read_balance(env, &token, &src)?.into(),
        );
    }

    for ((target, token), amount) in targets {
        // The tx must be authorized by the involved address
        env.insert_verifier(&target)?;
        if token.is_internal() {
            // Established address tokens do not have VPs themselves, their
            // validation is handled by the `Multitoken` internal address,
            // but internal token addresses have to verify
            // the transfer
            env.insert_verifier(&token)?;
        }
        evt_targets.insert(
            (UserAccount::Internal(target.clone()), token.clone()),
            amount.into(),
        );
        post_balances.insert(
            (UserAccount::Internal(target.clone()), token.clone()),
            crate::read_balance(env, &token, &target)?.into(),
        );
    }

    env.emit(TokenEvent {
        descriptor: event_desc,
        level: EventLevel::Tx,
        operation: TokenOperation::Transfer {
            sources: evt_sources,
            targets: evt_targets,
            post_balances,
        },
    });

    Ok(debited_accounts)
}

/// Apply a shielded transfer
pub fn apply_shielded_transfer<ENV>(
    env: &mut ENV,
    masp_section_ref: MaspTxId,
    debited_accounts: HashSet<Address>,
    tx_data: &BatchedTx,
) -> Result<()>
where
    ENV: TxEnv + EmitEvents + action::Write<Err = Error>,
{
    let shielded = tx_data
        .tx
        .get_masp_section(&masp_section_ref)
        .cloned()
        .ok_or_err_msg("Unable to find required shielded section in tx data")
        .inspect_err(|_err| {
            env.set_commitment_sentinel();
        })?;
    utils::handle_masp_tx(env, &shielded)
        .wrap_err("Encountered error while handling MASP transaction")?;
    ENV::update_masp_note_commitment_tree(&shielded)
        .wrap_err("Failed to update the MASP commitment tree")?;

    env.push_action(Action::Masp(MaspAction::MaspSectionRef(
        masp_section_ref,
    )))?;
    // Extract the debited accounts for the masp part of the transfer and
    // push the relative actions
    let vin_addresses =
        shielded
            .transparent_bundle()
            .map_or_else(Default::default, |bndl| {
                bndl.vin
                    .iter()
                    .map(|vin| vin.address)
                    .collect::<BTreeSet<_>>()
            });
    let masp_authorizers: Vec<_> = debited_accounts
        .into_iter()
        .filter(|account| {
            vin_addresses.contains(&masp::addr_taddr(account.clone()))
        })
        .collect();
    if masp_authorizers.len() != vin_addresses.len() {
        return Err(Error::SimpleMessage(
            "Transfer transaction does not debit all the expected accounts",
        ));
    }

    for authorizer in masp_authorizers {
        env.push_action(Action::Masp(MaspAction::MaspAuthorizer(authorizer)))?;
    }

    Ok(())
}
