//! Token validity predicate queries

use namada_core::ledger::storage::{DBIter, StorageHasher, DB};
use namada_core::ledger::storage_api;
use namada_core::ledger::storage_api::token::read_denom;
use namada_core::types::address::Address;
use namada_core::types::token;

use crate::ledger::queries::RequestCtx;

router! {TOKEN,
    ( "denomination" / [addr: Address] ) -> Option<token::Denomination> = denomination,
}

/// Get the number of decimal places (in base 10) for a
/// token specified by `addr`.
fn denomination<D, H>(
    ctx: RequestCtx<'_, D, H>,
    addr: Address,
) -> storage_api::Result<Option<token::Denomination>>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    read_denom(ctx.wl_storage, &addr)
}

#[cfg(any(test, feature = "async-client"))]
pub mod client_only_methods {
    use borsh::BorshDeserialize;

    use super::Token;
    use crate::ledger::queries::{Client, RPC};
    use crate::types::address::Address;
    use crate::types::token;

    impl Token {
        /// Get the balance of the given `token` belonging to the given `owner`.
        pub async fn balance<CLIENT>(
            &self,
            client: &CLIENT,
            token: &Address,
            owner: &Address,
        ) -> Result<token::Amount, <CLIENT as Client>::Error>
        where
            CLIENT: Client + Sync,
        {
            let balance_key = token::balance_key(token, owner);
            let response = RPC
                .shell()
                .storage_value(client, None, None, false, &balance_key)
                .await?;

            let balance = if response.data.is_empty() {
                token::Amount::zero()
            } else {
                token::Amount::try_from_slice(&response.data)
                    .unwrap_or_default()
            };
            Ok(balance)
        }
    }
}
