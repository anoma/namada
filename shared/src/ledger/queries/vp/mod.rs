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
    #[cfg(not(feature = "mainnet"))]
    use borsh::BorshDeserialize;
    #[cfg(not(feature = "mainnet"))]
    use namada_core::ledger::testnet_pow;

    use super::Vp;
    #[cfg(not(feature = "mainnet"))]
    use crate::ledger::queries::{Client, RPC};
    #[cfg(not(feature = "mainnet"))]
    use crate::types::address::Address;

    impl Vp {
        #[cfg(not(feature = "mainnet"))]
        /// Get faucet account address, if any is setup for the network.
        pub async fn get_faucet_address<CLIENT>(
            &self,
            client: &CLIENT,
        ) -> Result<Option<Address>, <CLIENT as Client>::Error>
        where
            CLIENT: Client + Sync,
        {
            let faucet_account_key = namada_core::ledger::parameters::storage::get_faucet_account_key();
            if RPC
                .shell()
                .storage_has_key(client, &faucet_account_key)
                .await?
            {
                let faucet_account = Address::try_from_slice(
                    &RPC.shell()
                        .storage_value(
                            client,
                            None,
                            None,
                            false,
                            &faucet_account_key,
                        )
                        .await?
                        .data,
                )
                .expect("Faucet address couldn't be read");
                Ok(Some(faucet_account))
            } else {
                Ok(None)
            }
        }

        #[cfg(not(feature = "mainnet"))]
        /// Check if the given address is a faucet account address.
        pub async fn is_faucet<CLIENT>(
            &self,
            client: &CLIENT,
            address: &Address,
        ) -> Result<bool, <CLIENT as Client>::Error>
        where
            CLIENT: Client + Sync,
        {
            if let Some(faucet_address) =
                self.get_faucet_address(client).await?
            {
                Ok(address == &faucet_address)
            } else {
                Ok(false)
            }
        }

        #[cfg(not(feature = "mainnet"))]
        /// Get a faucet PoW challenge for token withdrawal.
        pub async fn testnet_pow_challenge<CLIENT>(
            &self,
            client: &CLIENT,
            source: Address,
        ) -> Result<testnet_pow::Challenge, <CLIENT as Client>::Error>
        where
            CLIENT: Client + Sync,
        {
            let params = self.testnet_pow_params(client, &source).await?;
            Ok(testnet_pow::Challenge { source, params })
        }

        #[cfg(not(feature = "mainnet"))]
        /// Read faucet PoW challenge parameters for token withdrawal.
        pub async fn testnet_pow_params<CLIENT>(
            &self,
            client: &CLIENT,
            source: &Address,
        ) -> Result<testnet_pow::ChallengeParams, <CLIENT as Client>::Error>
        where
            CLIENT: Client + Sync,
        {
            let faucet_address = self
                .get_faucet_address(client)
                .await?
                .expect("No faucet account found");
            let difficulty_key = &testnet_pow::difficulty_key(&faucet_address);
            let counter_key = &testnet_pow::counters_handle(&faucet_address)
                .get_data_key(source);
            let difficulty = testnet_pow::Difficulty::try_from_slice(
                &RPC.shell()
                    .storage_value(client, None, None, false, difficulty_key)
                    .await?
                    .data,
            )
            .expect("Faucet PoW difficulty couldn't be read");
            let counter = if RPC
                .shell()
                .storage_has_key(client, counter_key)
                .await?
            {
                testnet_pow::Counter::try_from_slice(
                    &RPC.shell()
                        .storage_value(client, None, None, false, counter_key)
                        .await?
                        .data,
                )
                .expect("Faucet counter has unexpected encoding")
            } else {
                // `0` if not previously set (same as
                // `testnet_pow::get_counter`)
                testnet_pow::Counter::default()
            };

            Ok(testnet_pow::ChallengeParams {
                difficulty,
                counter,
            })
        }
    }
}
