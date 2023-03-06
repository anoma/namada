use borsh::{BorshDeserialize, BorshSerialize};
use namada_core::ledger::eth_bridge::storage::active_key;
use namada_core::ledger::eth_bridge::storage::bridge_pool::{
    get_nonce_key, get_signed_root_key,
};
use namada_core::ledger::storage;
use namada_core::ledger::storage::{StoreType, WlStorage};
use namada_core::ledger::storage_api::StorageRead;
use namada_core::types::address::Address;
use namada_core::types::ethereum_events::{EthAddress, Uint};
use namada_core::types::keccak::KeccakHash;
use namada_core::types::storage::{BlockHeight, Epoch};
use namada_core::types::token;
use namada_core::types::vote_extensions::validator_set_update::{
    EthAddrBook, ValidatorSetArgs, VotingPowersMap, VotingPowersMapExt,
};
use namada_core::types::voting_power::{
    EthBridgeVotingPower, FractionalVotingPower,
};
use namada_proof_of_stake::pos_queries::{ActiveValidators, PosQueries};
use namada_proof_of_stake::{
    validator_eth_cold_key_handle, validator_eth_hot_key_handle,
};

use crate::storage::proof::BridgePoolRootProof;

/// This enum is used as a parameter to
/// [`EthBridgeQueriesHook::must_send_valset_upd`].
pub enum SendValsetUpd {
    /// Check if it is possible to send a validator set update
    /// vote extension at the current block height.
    Now,
    /// Check if it is possible to send a validator set update
    /// vote extension at the previous block height.
    AtPrevHeight,
}

#[derive(Debug, Clone, BorshDeserialize, BorshSerialize)]
/// An enum indicating if the Ethereum bridge is enabled.
pub enum EthBridgeStatus {
    Disabled,
    Enabled(EthBridgeEnabled),
}

#[derive(Debug, Clone, BorshDeserialize, BorshSerialize)]
/// Enum indicating if the bridge was initialized at genesis
/// or a later epoch.
pub enum EthBridgeEnabled {
    AtGenesis,
    AtEpoch(
        // bridge is enabled from this epoch
        // onwards. a validator set proof must
        // exist for this epoch.
        Epoch,
    ),
}

/// Methods used to query blockchain Ethereum bridge related state.
pub trait EthBridgeQueries {
    /// The underlying storage type.
    type Storage;

    /// Return a handle to [`EthBridgeQueries`].
    fn ethbridge_queries(&self) -> EthBridgeQueriesHook<'_, Self::Storage>;
}

impl<D, H> EthBridgeQueries for WlStorage<D, H>
where
    D: storage::DB + for<'iter> storage::DBIter<'iter>,
    H: storage::StorageHasher,
{
    type Storage = Self;

    #[inline]
    fn ethbridge_queries(&self) -> EthBridgeQueriesHook<'_, Self> {
        EthBridgeQueriesHook { wl_storage: self }
    }
}

/// A handle to [`EthBridgeQueries`].
///
/// This type is a wrapper around a pointer to a
/// [`WlStorage`].
#[derive(Debug)]
#[repr(transparent)]
pub struct EthBridgeQueriesHook<'db, DB> {
    wl_storage: &'db DB,
}

impl<'db, DB> Clone for EthBridgeQueriesHook<'db, DB> {
    fn clone(&self) -> Self {
        Self {
            wl_storage: self.wl_storage,
        }
    }
}

impl<'db, DB> Copy for EthBridgeQueriesHook<'db, DB> {}

impl<'db, D, H> EthBridgeQueriesHook<'db, WlStorage<D, H>>
where
    D: storage::DB + for<'iter> storage::DBIter<'iter>,
    H: storage::StorageHasher,
{
    /// Return a handle to the inner [`WlStorage`].
    #[inline]
    pub fn storage(self) -> &'db WlStorage<D, H> {
        self.wl_storage
    }

    /// Check if the bridge is disabled, enabled, or
    /// scheduled to be enabled at a specified epoch.
    pub fn check_bridge_status(self) -> EthBridgeStatus {
        BorshDeserialize::try_from_slice(
            self.wl_storage
                .storage
                .read(&active_key())
                .expect(
                    "Reading the Ethereum bridge active key shouldn't fail.",
                )
                .0
                .expect("The Ethereum bridge active key should be in storage")
                .as_slice(),
        )
        .expect("Deserializing the Ethereum bridge active key shouldn't fail.")
    }

    /// Returns a boolean indicating whether the bridge
    /// is currently active.
    pub fn is_bridge_active(self) -> bool {
        match self.check_bridge_status() {
            EthBridgeStatus::Disabled => false,
            EthBridgeStatus::Enabled(EthBridgeEnabled::AtGenesis) => true,
            EthBridgeStatus::Enabled(EthBridgeEnabled::AtEpoch(
                enabled_epoch,
            )) => {
                let current_epoch =
                    self.wl_storage.storage.get_current_epoch().0;
                current_epoch >= enabled_epoch
            }
        }
    }

    /// Get the latest nonce for the Ethereum bridge
    /// pool.
    pub fn get_bridge_pool_nonce(self) -> Uint {
        Uint::try_from_slice(
            &self
                .wl_storage
                .storage
                .read(&get_nonce_key())
                .expect("Reading Bridge pool nonce shouldn't fail.")
                .0
                .expect("Reading Bridge pool nonce shouldn't fail."),
        )
        .expect("Deserializing the nonce from storage should not fail.")
    }

    /// Get the nonce at a particular block height.
    pub fn get_bridge_pool_nonce_at_height(self, height: BlockHeight) -> Uint {
        Uint::try_from_slice(
            &self
                .wl_storage
                .storage
                .db
                .read_subspace_val_with_height(
                    &get_nonce_key(),
                    height,
                    self.wl_storage.storage.last_height,
                )
                .expect("Reading signed Bridge pool nonce shouldn't fail.")
                .expect("Reading signed Bridge pool nonce shouldn't fail."),
        )
        .expect("Deserializing the signed nonce from storage should not fail.")
    }

    /// Get the latest root of the Ethereum bridge
    /// pool Merkle tree.
    pub fn get_bridge_pool_root(self) -> KeccakHash {
        self.wl_storage
            .storage
            .block
            .tree
            .sub_root(&StoreType::BridgePool)
            .into()
    }

    /// Get a quorum of validator signatures over
    /// the concatenation of the latest bridge pool
    /// root and nonce.
    ///
    /// Also returns the block height at which the
    /// a quorum of signatures was collected.
    ///
    /// No value exists when the bridge if first
    /// started.
    pub fn get_signed_bridge_pool_root(
        self,
    ) -> Option<(BridgePoolRootProof, BlockHeight)> {
        self.wl_storage
            .read_bytes(&get_signed_root_key())
            .expect("Reading signed Bridge pool root shouldn't fail.")
            .map(|bytes| {
                BorshDeserialize::try_from_slice(&bytes).expect(
                    "Deserializing the signed bridge pool root from storage \
                     should not fail.",
                )
            })
    }

    /// Get the root of the Ethereum bridge
    /// pool Merkle tree at a given height.
    pub fn get_bridge_pool_root_at_height(
        self,
        height: BlockHeight,
    ) -> KeccakHash {
        self.wl_storage
            .storage
            .db
            .read_merkle_tree_stores(height)
            .expect("We should always be able to read the database")
            .expect("Every root should correspond to an existing block height")
            .get_root(StoreType::BridgePool)
            .into()
    }

    /// Determines if it is possible to send a validator set update vote
    /// extension at the provided [`BlockHeight`] in [`SendValsetUpd`].
    #[cfg(feature = "abcipp")]
    #[inline]
    pub fn must_send_valset_upd(self, can_send: SendValsetUpd) -> bool {
        if matches!(can_send, SendValsetUpd::Now) {
            self.wl_storage
                .pos_queries()
                .is_deciding_offset_within_epoch(1)
        } else {
            // TODO: implement this method for ABCI++; should only be able to
            // send a validator set update at the second block of an
            // epoch
            false
        }
    }

    /// Determines if it is possible to send a validator set update vote
    /// extension at the provided [`BlockHeight`] in [`SendValsetUpd`].
    #[cfg(not(feature = "abcipp"))]
    #[inline]
    pub fn must_send_valset_upd(self, can_send: SendValsetUpd) -> bool {
        if matches!(can_send, SendValsetUpd::AtPrevHeight) {
            // when checking vote extensions in Prepare
            // and ProcessProposal, we simply return true
            true
        } else {
            // offset of 1 => are we at the 2nd
            // block within the epoch?
            self.wl_storage
                .pos_queries()
                .is_deciding_offset_within_epoch(1)
        }
    }

    /// For a given Namada validator, return its corresponding Ethereum bridge
    /// address.
    #[inline]
    pub fn get_ethbridge_from_namada_addr(
        self,
        validator: &Address,
        epoch: Option<Epoch>,
    ) -> Option<EthAddress> {
        let epoch = epoch
            .unwrap_or_else(|| self.wl_storage.storage.get_current_epoch().0);
        let params = self.wl_storage.pos_queries().get_pos_params();
        validator_eth_hot_key_handle(validator)
            .get(self.wl_storage, epoch, &params)
            .expect("Should be able to read eth hot key from storage")
            .and_then(|ref pk| pk.try_into().ok())
    }

    /// For a given Namada validator, return its corresponding Ethereum
    /// governance address.
    #[inline]
    pub fn get_ethgov_from_namada_addr(
        self,
        validator: &Address,
        epoch: Option<Epoch>,
    ) -> Option<EthAddress> {
        let epoch = epoch
            .unwrap_or_else(|| self.wl_storage.storage.get_current_epoch().0);
        let params = self.wl_storage.pos_queries().get_pos_params();
        validator_eth_cold_key_handle(validator)
            .get(self.wl_storage, epoch, &params)
            .expect("Should be able to read eth cold key from storage")
            .and_then(|ref pk| pk.try_into().ok())
    }

    /// For a given Namada validator, return its corresponding Ethereum
    /// address book.
    #[inline]
    pub fn get_eth_addr_book(
        self,
        validator: &Address,
        epoch: Option<Epoch>,
    ) -> Option<EthAddrBook> {
        let bridge = self.get_ethbridge_from_namada_addr(validator, epoch)?;
        let governance = self.get_ethgov_from_namada_addr(validator, epoch)?;
        Some(EthAddrBook {
            hot_key_addr: bridge,
            cold_key_addr: governance,
        })
    }

    /// Extension of [`Self::get_active_validators`], which additionally returns
    /// all Ethereum addresses of some validator.
    #[inline]
    pub fn get_active_eth_addresses(
        self,
        epoch: Option<Epoch>,
    ) -> ActiveEthAddresses<'db, D, H> {
        let epoch = epoch
            .unwrap_or_else(|| self.wl_storage.storage.get_current_epoch().0);
        let active_validators = self
            .wl_storage
            .pos_queries()
            .get_active_validators(Some(epoch));
        ActiveEthAddresses {
            wl_storage: self.wl_storage,
            active_validators,
            epoch,
        }
    }

    /// Query the active [`ValidatorSetArgs`] at the given [`Epoch`].
    /// Also returns a map of each validator's voting power.
    pub fn get_validator_set_args(
        self,
        epoch: Option<Epoch>,
    ) -> (ValidatorSetArgs, VotingPowersMap) {
        let epoch = epoch
            .unwrap_or_else(|| self.wl_storage.storage.get_current_epoch().0);

        let voting_powers_map: VotingPowersMap = self
            .get_active_eth_addresses(Some(epoch))
            .iter()
            .map(|(addr_book, _, power)| (addr_book, power))
            .collect();

        let total_power = self
            .wl_storage
            .pos_queries()
            .get_total_voting_power(Some(epoch))
            .into();
        let (validators, voting_powers) = voting_powers_map
            .get_sorted()
            .into_iter()
            .map(|(&EthAddrBook { hot_key_addr, .. }, &power)| {
                let voting_power: EthBridgeVotingPower =
                    FractionalVotingPower::new(power.into(), total_power)
                        .expect("Fractional voting power should be >1")
                        .into();
                (hot_key_addr, voting_power)
            })
            .unzip();

        (
            ValidatorSetArgs {
                epoch,
                validators,
                voting_powers,
            },
            voting_powers_map,
        )
    }
}

/// A handle to the Ethereum addresses of the set of active
/// validators in Namada, at some given epoch.
pub struct ActiveEthAddresses<'db, D, H>
where
    D: storage::DB + for<'iter> storage::DBIter<'iter>,
    H: storage::StorageHasher,
{
    epoch: Epoch,
    wl_storage: &'db WlStorage<D, H>,
    active_validators: ActiveValidators<'db, D, H>,
}

impl<'db, D, H> ActiveEthAddresses<'db, D, H>
where
    D: storage::DB + for<'iter> storage::DBIter<'iter>,
    H: storage::StorageHasher,
{
    /// Iterate over the Ethereum addresses of the set of active validators
    /// in Namada, at some given epoch.
    pub fn iter<'this: 'db>(
        &'this self,
    ) -> impl Iterator<Item = (EthAddrBook, Address, token::Amount)> + 'db {
        self.active_validators.iter().map(move |validator| {
            let hot_key_addr = self
                .wl_storage
                .ethbridge_queries()
                .get_ethbridge_from_namada_addr(
                    &validator.address,
                    Some(self.epoch),
                )
                .expect(
                    "All Namada validators should have an Ethereum bridge key",
                );
            let cold_key_addr = self
                .wl_storage
                .ethbridge_queries()
                .get_ethgov_from_namada_addr(
                    &validator.address,
                    Some(self.epoch),
                )
                .expect(
                    "All Namada validators should have an Ethereum governance \
                     key",
                );
            let eth_addr_book = EthAddrBook {
                hot_key_addr,
                cold_key_addr,
            };
            (eth_addr_book, validator.address, validator.bonded_stake)
        })
    }
}
