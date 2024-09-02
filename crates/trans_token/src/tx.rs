//! Token transfers

use namada_core::address::Address;
use namada_events::{EmitEvents, EventLevel};
use namada_tx_env::{Result, TxEnv};

use crate::event::{TokenEvent, TokenOperation};
use crate::{Amount, UserAccount};

/// Transfer transparent token, insert the verifier expected by the VP and an
/// emit an event.
pub fn transfer<ENV>(
    env: &mut ENV,
    src: &Address,
    dest: &Address,
    token: &Address,
    amount: Amount,
) -> Result<()>
where
    ENV: TxEnv + EmitEvents,
{
    // The tx must be authorized by the source and destination addresses
    env.insert_verifier(src)?;
    env.insert_verifier(dest)?;
    if token.is_internal() {
        // Established address tokens do not have VPs themselves, their
        // validation is handled by the `Multitoken` internal address, but
        // internal token addresses have to verify the transfer
        env.insert_verifier(token)?;
    }

    crate::storage::transfer(env, token, src, dest, amount)?;

    env.emit(TokenEvent {
        descriptor: "transfer-from-wasm".into(),
        level: EventLevel::Tx,
        operation: TokenOperation::transfer(
            UserAccount::Internal(src.clone()),
            UserAccount::Internal(dest.clone()),
            token.clone(),
            amount.into(),
            crate::read_balance(env, token, src)?.into(),
            Some(crate::read_balance(env, token, dest)?.into()),
        ),
    });

    Ok(())
}
