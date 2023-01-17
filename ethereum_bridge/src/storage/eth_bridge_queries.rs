use borsh::BorshDeserialize;
use namada_core::ledger::eth_bridge::storage::bridge_pool::get_nonce_key;
use namada_core::ledger::storage;
use namada_core::ledger::storage::{Storage, StoreType};
use namada_core::types::address::Address;
use namada_core::types::ethereum_events::{EthAddress, Uint};
use namada_core::types::keccak::KeccakHash;
use namada_core::types::storage::{BlockHeight, Epoch};
use namada_core::types::token;
use namada_core::types::vote_extensions::validator_set_update::EthAddrBook;
use namada_proof_of_stake::pos_queries::PosQueries;
use namada_proof_of_stake::PosBase;

/// This enum is used as a parameter to
/// [`EthBridgeQueries::must_send_valset_upd`].
pub enum SendValsetUpd {
    /// Check if it is possible to send a validator set update
    /// vote extension at the current block height.
    Now,
    /// Check if it is possible to send a validator set update
    /// vote extension at the previous block height.
    AtPrevHeight,
}

pub trait EthBridgeQueries {
    /// Fetch the first [`BlockHeight`] of the last [`Epoch`]
    /// committed to storage.
    fn get_epoch_start_height(&self) -> BlockHeight;

    /// Get the latest nonce for the Ethereum bridge
    /// pool.
    fn get_bridge_pool_nonce(&self) -> Uint;

    /// Get the latest root of the Ethereum bridge
    /// pool Merkle tree.
    fn get_bridge_pool_root(&self) -> KeccakHash;

    /// Get the root of the Ethereum bridge
    /// pool Merkle tree at a given height.
    fn get_bridge_pool_root_at_height(&self, height: BlockHeight)
    -> KeccakHash;

    /// Determines if it is possible to send a validator set update vote
    /// extension at the provided [`BlockHeight`] in [`SendValsetUpd`].
    fn must_send_valset_upd(&self, can_send: SendValsetUpd) -> bool;

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
    #[inline]
    fn get_epoch_start_height(&self) -> BlockHeight {
        // NOTE: the first stored height in `fst_block_heights_of_each_epoch`
        // is 0, because of a bug (should be 1), so this code needs to
        // handle that case
        //
        // we can remove this check once that's fixed
        if self.last_epoch.0 == 0 {
            return BlockHeight(1);
        }
        self.block
            .pred_epochs
            .first_block_heights()
            .last()
            .copied()
            .expect("The block height of the current epoch should be known")
    }

    fn get_bridge_pool_nonce(&self) -> Uint {
        Uint::try_from_slice(
            &self
                .read(&get_nonce_key())
                .expect("Reading Bridge pool nonce shouldn't fail.")
                .0
                .expect("Reading Bridge pool nonce shouldn't fail."),
        )
        .expect("Deserializing the nonce from storage should not fail.")
    }

    fn get_bridge_pool_root(&self) -> KeccakHash {
        self.block.tree.sub_root(&StoreType::BridgePool).into()
    }

    fn get_bridge_pool_root_at_height(
        &self,
        height: BlockHeight,
    ) -> KeccakHash {
        self.db
            .read_merkle_tree_stores(height)
            .expect("We should always be able to read the database")
            .expect("Every root should correspond to an existing block height")
            .get_root(StoreType::BridgePool)
            .into()
    }

    #[cfg(feature = "abcipp")]
    #[inline]
    fn must_send_valset_upd(&self, can_send: SendValsetUpd) -> bool {
        if matches!(can_send, SendValsetUpd::Now) {
            self.is_deciding_offset_within_epoch(1)
        } else {
            // TODO: implement this method for ABCI++; should only be able to
            // send a validator set update at the second block of an
            // epoch
            false
        }
    }

    #[cfg(not(feature = "abcipp"))]
    #[inline]
    fn must_send_valset_upd(&self, can_send: SendValsetUpd) -> bool {
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
