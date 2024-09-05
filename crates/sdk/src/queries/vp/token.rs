//! Token validity predicate queries

use namada_core::address::Address;
use namada_core::token;
use namada_state::{DBIter, StorageHasher, DB};
use namada_token::{
    get_effective_total_native_supply, read_denom, read_total_supply,
};

use crate::queries::RequestCtx;

router! {TOKEN,
    ( "denomination" / [token: Address] ) -> Option<token::Denomination> = denomination,
    ( "total_supply" / [token: Address] ) -> token::Amount = total_supply,
    ( "effective_native_supply" ) -> token::Amount = effective_native_supply,
}

/// Get the number of decimal places (in base 10) for a
/// token specified by `addr`.
fn denomination<D, H, V, T>(
    ctx: RequestCtx<'_, D, H, V, T>,
    token: Address,
) -> namada_storage::Result<Option<token::Denomination>>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    read_denom(ctx.state, &token)
}

/// Get the total supply for a token address
fn total_supply<D, H, V, T>(
    ctx: RequestCtx<'_, D, H, V, T>,
    token: Address,
) -> namada_storage::Result<token::Amount>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    read_total_supply(ctx.state, &token)
}

/// Get the effective total supply of the native token
fn effective_native_supply<D, H, V, T>(
    ctx: RequestCtx<'_, D, H, V, T>,
) -> namada_storage::Result<token::Amount>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    get_effective_total_native_supply(ctx.state)
}

pub mod client_only_methods {
    use borsh::BorshDeserialize;
    use namada_core::address::Address;
    use namada_core::token;
    use namada_io::Client;
    use namada_token::storage_key::{balance_key, masp_total_rewards};

    use super::Token;
    use crate::queries::RPC;

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
            let balance_key = balance_key(token, owner);
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

        /// Get the total rewards minted by MASP.
        pub async fn masp_total_rewards<CLIENT>(
            &self,
            client: &CLIENT,
        ) -> Result<token::Amount, <CLIENT as Client>::Error>
        where
            CLIENT: Client + Sync,
        {
            let total_rewards_key = masp_total_rewards();
            let response = RPC
                .shell()
                .storage_value(client, None, None, false, &total_rewards_key)
                .await?;

            let tokens = if response.data.is_empty() {
                token::Amount::zero()
            } else {
                token::Amount::try_from_slice(&response.data)
                    .unwrap_or_default()
            };
            Ok(tokens)
        }
    }
}
