use namada_core::ledger::storage;
use namada_core::ledger::storage::Storage;
use namada_core::types::address::Address;
use namada_core::types::ethereum_events::EthAddress;
use namada_core::types::storage::Epoch;
use namada_core::types::token;
use namada_core::types::vote_extensions::validator_set_update::EthAddrBook;
use namada_proof_of_stake::pos_queries::PosQueries;
use namada_proof_of_stake::PosBase;

/// This enum is used as a parameter to
/// [`PosQueries::can_send_validator_set_update`].
pub enum SendValsetUpd {
    /// Check if it is possible to send a validator set update
    /// vote extension at the current block height.
    Now,
    /// Check if it is possible to send a validator set update
    /// vote extension at the previous block height.
    AtPrevHeight,
}

pub trait EthBridgeQueries: PosQueries {
    /// Determines if it is possible to send a validator set update vote
    /// extension at the provided [`BlockHeight`] in [`SendValsetUpd`].
    fn can_send_validator_set_update(&self, can_send: SendValsetUpd) -> bool;

    /// For a given Namada validator, return its corresponding Ethereum bridge
    /// address.
    fn get_ethbridge_from_namada_addr(
        &self,
        validator: &Address,
        epoch: Option<Epoch>,
    ) -> Option<EthAddress>;

    /// For a given Namada validator, return its corresponding Ethereum
    /// governance address.
    fn get_ethgov_from_namada_addr(
        &self,
        validator: &Address,
        epoch: Option<Epoch>,
    ) -> Option<EthAddress>;

    /// Extension of [`Self::get_active_validators`], which additionally returns
    /// all Ethereum addresses of some validator.
    fn get_active_eth_addresses<'db>(
        &'db self,
        epoch: Option<Epoch>,
    ) -> Box<dyn Iterator<Item = (EthAddrBook, Address, token::Amount)> + 'db>;
}

impl<D, H> EthBridgeQueries for Storage<D, H>
where
    D: storage::DB + for<'iter> storage::DBIter<'iter>,
    H: storage::StorageHasher,
{
    #[cfg(feature = "abcipp")]
    #[inline]
    fn can_send_validator_set_update(&self, _can_send: SendValsetUpd) -> bool {
        // TODO: implement this method for ABCI++; should only be able to send
        // a validator set update at the second block of an epoch
        false
    }

    #[cfg(not(feature = "abcipp"))]
    #[inline]
    fn can_send_validator_set_update(&self, can_send: SendValsetUpd) -> bool {
        if matches!(can_send, SendValsetUpd::AtPrevHeight) {
            // when checking vote extensions in Prepare
            // and ProcessProposal, we simply return true
            true
        } else {
            // offset of 1 => are we at the 2nd
            // block within the epoch?
            self.is_deciding_offset_within_epoch(1)
        }
    }

    #[inline]
    fn get_ethbridge_from_namada_addr(
        &self,
        validator: &Address,
        epoch: Option<Epoch>,
    ) -> Option<EthAddress> {
        let epoch = epoch.unwrap_or_else(|| self.get_current_epoch().0);
        self.read_validator_eth_hot_key(validator)
            .as_ref()
            .and_then(|epk| epk.get(epoch).and_then(|pk| pk.try_into().ok()))
    }

    #[inline]
    fn get_ethgov_from_namada_addr(
        &self,
        validator: &Address,
        epoch: Option<Epoch>,
    ) -> Option<EthAddress> {
        let epoch = epoch.unwrap_or_else(|| self.get_current_epoch().0);
        self.read_validator_eth_cold_key(validator)
            .as_ref()
            .and_then(|epk| epk.get(epoch).and_then(|pk| pk.try_into().ok()))
    }

    #[inline]
    fn get_active_eth_addresses<'db>(
        &'db self,
        epoch: Option<Epoch>,
    ) -> Box<dyn Iterator<Item = (EthAddrBook, Address, token::Amount)> + 'db>
    {
        let epoch = epoch.unwrap_or_else(|| self.get_current_epoch().0);
        Box::new(self.get_active_validators(Some(epoch)).into_iter().map(
            move |validator| {
                let hot_key_addr = self
                    .get_ethbridge_from_namada_addr(
                        &validator.address,
                        Some(epoch),
                    )
                    .expect(
                        "All Namada validators should have an Ethereum bridge \
                         key",
                    );
                let cold_key_addr = self
                    .get_ethgov_from_namada_addr(
                        &validator.address,
                        Some(epoch),
                    )
                    .expect(
                        "All Namada validators should have an Ethereum \
                         governance key",
                    );
                let eth_addr_book = EthAddrBook {
                    hot_key_addr,
                    cold_key_addr,
                };
                (
                    eth_addr_book,
                    validator.address,
                    validator.bonded_stake.into(),
                )
            },
        ))
    }
}
