// Re-export to show in rustdoc!
pub use pos::Pos;
use pos::POS;
mod pos;

// Validity predicate queries
router! {VP,
    ( "pos" ) = (sub POS),
}

#[cfg(any(test, feature = "async-client"))]
pub mod client_only_methods {
    use borsh::BorshDeserialize;
    use namada_core::ledger::faucet_pow;
    use namada_core::types::token;

    use super::Vp;
    use crate::ledger::queries::{Client, RPC};
    use crate::types::address::Address;

    impl Vp {
        /// Check if the given address is a faucet account address by checking
        /// if it contains PoW `difficulty` field in its storage.
        pub async fn is_faucet<CLIENT>(
            &self,
            client: &CLIENT,
            address: &Address,
        ) -> Result<bool, <CLIENT as Client>::Error>
        where
            CLIENT: Client + Sync,
        {
            let difficulty_key = &faucet_pow::difficulty_key(address);
            RPC.shell().storage_has_key(client, difficulty_key).await
        }

        /// Get a faucet PoW challenge for token withdrawal.
        pub async fn faucet_pow_challenge<CLIENT>(
            &self,
            client: &CLIENT,
            transfer: token::Transfer,
        ) -> Result<faucet_pow::Challenge, <CLIENT as Client>::Error>
        where
            CLIENT: Client + Sync,
        {
            let params = self
                .faucet_pow_params(client, &transfer.source, &transfer.target)
                .await?;
            Ok(faucet_pow::Challenge { transfer, params })
        }

        /// Read faucet PoW challenge parameters for token withdrawal.
        pub async fn faucet_pow_params<CLIENT>(
            &self,
            client: &CLIENT,
            faucet_address: &Address,
            transfer_target: &Address,
        ) -> Result<faucet_pow::ChallengeParams, <CLIENT as Client>::Error>
        where
            CLIENT: Client + Sync,
        {
            let difficulty_key = &faucet_pow::difficulty_key(faucet_address);
            let counter_key = &faucet_pow::counters_handle(faucet_address)
                .get_data_key(transfer_target);
            let difficulty = faucet_pow::Difficulty::try_from_slice(
                &RPC.shell()
                    .storage_value(client, None, None, false, difficulty_key)
                    .await?
                    .data,
            )
            .expect("Faucet PoW difficulty couldn't get read");
            let counter = if RPC
                .shell()
                .storage_has_key(client, counter_key)
                .await?
            {
                faucet_pow::Counter::try_from_slice(
                    &RPC.shell()
                        .storage_value(client, None, None, false, counter_key)
                        .await?
                        .data,
                )
                .expect("Faucet counter has unexpected encoding")
            } else {
                // `0` if not previously set (same as `faucet_pow::get_counter`)
                faucet_pow::Counter::default()
            };

            Ok(faucet_pow::ChallengeParams {
                difficulty,
                counter,
            })
        }
    }
}
