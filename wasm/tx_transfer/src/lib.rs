//! A tx for transparent token transfer.
//! This tx uses `token::TransparentTransfer` wrapped inside `SignedTxData`
//! as its input as declared in `namada` crate.

use std::collections::{BTreeMap, BTreeSet};

use namada_tx_prelude::action::{Action, MaspAction, Write};
use namada_tx_prelude::masp::addr_taddr;
use namada_tx_prelude::*;

#[transaction]
fn apply_tx(ctx: &mut Ctx, tx_data: BatchedTx) -> TxResult {
    let data = ctx.get_tx_data(&tx_data)?;
    let transfers = token::Transfer::try_from_slice(&data[..])
        .wrap_err("Failed to decode token::TransparentTransfer tx data")?;
    debug_log!("apply_tx called with transfer: {:#?}", transfers);

    // Prepare the sources of the multi-transfer
    let sources = transfers
        .sources
        .into_iter()
        .map(|(account, amount)| {
            ((account.owner, account.token), amount.amount())
        })
        .collect::<BTreeMap<_, _>>();

    // Prepare the target of the multi-transfer
    let targets = transfers
        .targets
        .into_iter()
        .map(|(account, amount)| {
            ((account.owner, account.token), amount.amount())
        })
        .collect::<BTreeMap<_, _>>();

    // Effect the multi transfer
    let debited_accounts = token::multi_transfer(ctx, &sources, &targets)
        .wrap_err("Token transfer failed")?;

    // Apply the shielded transfer if there is a link to one
    if let Some(masp_section_ref) = transfers.shielded_section_hash {
        let shielded = tx_data
            .tx
            .get_masp_section(&masp_section_ref)
            .cloned()
            .ok_or_err_msg(
                "Unable to find required shielded section in tx data",
            )
            .inspect_err(|_| {
                ctx.set_commitment_sentinel();
            })?;
        token::utils::handle_masp_tx(ctx, &shielded)
            .wrap_err("Encountered error while handling MASP transaction")?;
        update_masp_note_commitment_tree(&shielded)
            .wrap_err("Failed to update the MASP commitment tree")?;

        ctx.push_action(Action::Masp(MaspAction::MaspSectionRef(
            masp_section_ref,
        )))?;
        // Extract the debited accounts for the masp part of the transfer and
        // push the relative actions
        let vin_addresses = shielded.transparent_bundle().map_or_else(
            Default::default,
            |bndl| {
                bndl.vin
                    .iter()
                    .map(|vin| vin.address)
                    .collect::<BTreeSet<_>>()
            },
        );
        let masp_authorizers: Vec<_> = debited_accounts
            .into_iter()
            .filter(|account| {
                vin_addresses.contains(&addr_taddr(account.clone()))
            })
            .collect();
        if masp_authorizers.len() != vin_addresses.len() {
            return Err(Error::SimpleMessage(
                "Transfer transaction does not debit all the expected accounts",
            ));
        }

        for authorizer in masp_authorizers {
            ctx.push_action(Action::Masp(MaspAction::MaspAuthorizer(
                authorizer,
            )))?;
        }
    }

    Ok(())
}
