//! [`Epoched`] and [`EpochedDelta`] are structures for data that is set for
//! future (and possibly past) epochs.

use std::collections::HashMap;
use std::fmt::Debug;
use std::marker::PhantomData;
use std::ops;

use borsh::{BorshDeserialize, BorshSchema, BorshSerialize};
use namada_core::ledger::storage_api;
use namada_core::ledger::storage_api::collections::lazy_map::{
    LazyMap, NestedMap,
};
use namada_core::ledger::storage_api::collections::{self, LazyCollection};
use namada_core::ledger::storage_api::{StorageRead, StorageWrite};
use namada_core::types::storage::{self, Epoch};

use crate::parameters::{PosAndGovParams, PosParams};
use crate::read_pos_and_gov_params;

/// Sub-key holding a lazy map in storage
pub const LAZY_MAP_SUB_KEY: &str = "lazy_map";
/// Sub-key for an epoched data structure's last (most recent) epoch of update
pub const LAST_UPDATE_SUB_KEY: &str = "last_update";
/// Sub-key for an epoched data structure's oldest epoch with some data
pub const OLDEST_EPOCH_SUB_KEY: &str = "oldest_epoch";

/// Default number of past epochs to keep.
const DEFAULT_NUM_PAST_EPOCHS: u64 = 2;

/// Discrete epoched data handle
pub struct Epoched<Data, FutureEpochs, PastEpochs, SON = collections::Simple> {
    storage_prefix: storage::Key,
    future_epochs: PhantomData<FutureEpochs>,
    past_epochs: PhantomData<PastEpochs>,
    data: PhantomData<Data>,
    phantom_son: PhantomData<SON>,
}

/// Discrete epoched data handle with nested lazy structure
pub type NestedEpoched<Data, FutureEpochs, PastEpochs> =
    Epoched<Data, FutureEpochs, PastEpochs, collections::Nested>;

/// Delta epoched data handle
pub struct EpochedDelta<Data, FutureEpochs, PastEpochs> {
    storage_prefix: storage::Key,
    future_epochs: PhantomData<FutureEpochs>,
    past_epochs: PhantomData<PastEpochs>,
    data: PhantomData<Data>,
}

impl<Data, FutureEpochs, PastEpochs, SON>
    Epoched<Data, FutureEpochs, PastEpochs, SON>
where
    FutureEpochs: EpochOffset,
    PastEpochs: EpochOffset,
{
    /// Open the handle
    pub fn open(key: storage::Key) -> Self {
        Self {
            storage_prefix: key,
            future_epochs: PhantomData,
            past_epochs: PhantomData,
            data: PhantomData,
            phantom_son: PhantomData,
        }
    }
}

impl<Data, FutureEpochs, PastEpochs> Epoched<Data, FutureEpochs, PastEpochs>
where
    FutureEpochs: EpochOffset,
    PastEpochs: EpochOffset,
    Data: BorshSerialize + BorshDeserialize + 'static + Debug,
{
    /// Initialize new epoched data. Sets the head to the given value.
    /// This should only be used at genesis.
    pub fn init_at_genesis<S>(
        &self,
        storage: &mut S,
        value: Data,
        current_epoch: Epoch,
    ) -> storage_api::Result<()>
    where
        S: StorageWrite + StorageRead,
    {
        let key = self.get_last_update_storage_key();
        storage.write(&key, current_epoch)?;
        self.set_oldest_epoch(storage, current_epoch)?;
        self.set_at_epoch(storage, value, current_epoch, 0)
    }

    /// Find the value for the given epoch or a nearest epoch before it.
    pub fn get<S>(
        &self,
        storage: &S,
        epoch: Epoch,
        params: &PosAndGovParams,
    ) -> storage_api::Result<Option<Data>>
    where
        S: StorageRead,
    {
        let last_update = self.get_last_update(storage)?;
        match last_update {
            None => Ok(None),
            Some(last_update) => {
                let data_handler = self.get_data_handler();
                let future_most_epoch =
                    last_update + FutureEpochs::value(params);
                // Epoch can be a lot greater than the epoch where
                // a value is recorded, we check the upper bound
                // epoch of the LazyMap data
                let mut epoch = std::cmp::min(epoch, future_most_epoch);
                loop {
                    let res = data_handler.get(storage, &epoch)?;
                    match res {
                        Some(_) => return Ok(res),
                        None => {
                            if epoch.0 > 0
                                && epoch
                                    > Self::sub_past_epochs(params, last_update)
                            {
                                epoch = Epoch(epoch.0 - 1);
                            } else {
                                return Ok(None);
                            }
                        }
                    }
                }
            }
        }
    }

    /// Initialize or set the value at the given epoch offset.
    pub fn set<S>(
        &self,
        storage: &mut S,
        value: Data,
        current_epoch: Epoch,
        offset: u64,
    ) -> storage_api::Result<()>
    where
        S: StorageWrite + StorageRead,
    {
        let params = read_pos_and_gov_params(storage)?;
        self.update_data(storage, &params, current_epoch)?;
        self.set_at_epoch(storage, value, current_epoch, offset)
    }

    fn set_at_epoch<S>(
        &self,
        storage: &mut S,
        value: Data,
        current_epoch: Epoch,
        offset: u64,
    ) -> storage_api::Result<()>
    where
        S: StorageWrite + StorageRead,
    {
        let data_handler = self.get_data_handler();
        let epoch = current_epoch + offset;
        let _prev = data_handler.insert(storage, epoch, value)?;
        Ok(())
    }

    /// Update the data associated with epochs to trim historical data, if
    /// needed. Any value with epoch before the oldest stored epoch to be
    /// kept is dropped. If the oldest stored epoch is not already
    /// associated with some value, the latest value from the dropped
    /// values, if any, is associated with it.
    fn update_data<S>(
        &self,
        storage: &mut S,
        params: &PosAndGovParams,
        current_epoch: Epoch,
    ) -> storage_api::Result<()>
    where
        S: StorageWrite + StorageRead,
    {
        let last_update = self.get_last_update(storage)?;
        let oldest_epoch = self.get_oldest_epoch(storage)?;
        if let (Some(last_update), Some(oldest_epoch)) =
            (last_update, oldest_epoch)
        {
            let oldest_to_keep = current_epoch
                .0
                .checked_sub(PastEpochs::value(params))
                .unwrap_or_default();
            if oldest_epoch.0 < oldest_to_keep {
                let diff = oldest_to_keep - oldest_epoch.0;
                // Go through the epochs before the expected oldest epoch and
                // keep the latest one
                tracing::debug!(
                    "Trimming data for epoched data in epoch {current_epoch}, \
                     last updated at {last_update}."
                );
                let data_handler = self.get_data_handler();
                let mut latest_value: Option<Data> = None;
                // Remove data before the new oldest epoch, keep the latest
                // value
                for epoch in oldest_epoch.iter_range(diff) {
                    let removed = data_handler.remove(storage, &epoch)?;
                    if removed.is_some() {
                        tracing::debug!("Removed value at epoch {epoch}");
                        latest_value = removed;
                    }
                }
                if let Some(latest_value) = latest_value {
                    let new_oldest_epoch =
                        Self::sub_past_epochs(params, current_epoch);
                    // TODO we can add `contains_key` to LazyMap
                    if data_handler.get(storage, &new_oldest_epoch)?.is_none() {
                        tracing::debug!(
                            "Setting latest value at epoch \
                             {new_oldest_epoch}: {latest_value:?}"
                        );
                        data_handler.insert(
                            storage,
                            new_oldest_epoch,
                            latest_value,
                        )?;
                    }
                    self.set_oldest_epoch(storage, new_oldest_epoch)?;
                }
                // Update the epoch of the last update to the current epoch
                let key = self.get_last_update_storage_key();
                storage.write(&key, current_epoch)?;
                return Ok(());
            }
        }

        // Set the epoch of the last update to the current epoch
        let key = self.get_last_update_storage_key();
        storage.write(&key, current_epoch)?;

        // If there's no oldest epoch written yet, set it to the current one
        if oldest_epoch.is_none() {
            self.set_oldest_epoch(storage, current_epoch)?;
        }
        Ok(())
    }

    fn get_last_update_storage_key(&self) -> storage::Key {
        self.storage_prefix
            .push(&LAST_UPDATE_SUB_KEY.to_owned())
            .unwrap()
    }

    fn get_last_update<S>(
        &self,
        storage: &S,
    ) -> storage_api::Result<Option<Epoch>>
    where
        S: StorageRead,
    {
        let key = self.get_last_update_storage_key();
        storage.read(&key)
    }

    fn get_data_handler(&self) -> LazyMap<Epoch, Data> {
        let key = self
            .storage_prefix
            .push(&LAZY_MAP_SUB_KEY.to_owned())
            .unwrap();
        LazyMap::open(key)
    }

    fn sub_past_epochs(params: &PosAndGovParams, epoch: Epoch) -> Epoch {
        Epoch(
            epoch
                .0
                .checked_sub(PastEpochs::value(params))
                .unwrap_or_default(),
        )
    }

    fn get_oldest_epoch_storage_key(&self) -> storage::Key {
        self.storage_prefix
            .push(&OLDEST_EPOCH_SUB_KEY.to_owned())
            .unwrap()
    }

    fn get_oldest_epoch<S>(
        &self,
        storage: &S,
    ) -> storage_api::Result<Option<Epoch>>
    where
        S: StorageRead,
    {
        let key = self.get_oldest_epoch_storage_key();
        storage.read(&key)
    }

    fn set_oldest_epoch<S>(
        &self,
        storage: &mut S,
        new_oldest_epoch: Epoch,
    ) -> storage_api::Result<()>
    where
        S: StorageRead + StorageWrite,
    {
        let key = self.get_oldest_epoch_storage_key();
        storage.write(&key, new_oldest_epoch)
    }
}

impl<Data, FutureEpochs, PastEpochs>
    Epoched<Data, FutureEpochs, PastEpochs, collections::Nested>
where
    FutureEpochs: EpochOffset,
    PastEpochs: EpochOffset,
    Data: LazyCollection + Debug,
{
    /// Get the inner LazyCollection value by the outer key
    pub fn at(&self, key: &Epoch) -> Data {
        Data::open(self.get_data_handler().get_data_key(key))
    }

    /// Get handle to the NestedMap data itself
    pub fn get_data_handler(&self) -> NestedMap<Epoch, Data> {
        let key = self
            .storage_prefix
            .push(&LAZY_MAP_SUB_KEY.to_owned())
            .unwrap();
        NestedMap::open(key)
    }

    /// Initialize new nested data at the given epoch offset.
    pub fn init<S>(
        &self,
        storage: &mut S,
        epoch: Epoch,
    ) -> storage_api::Result<()>
    where
        S: StorageWrite + StorageRead,
    {
        let key = self.get_last_update_storage_key();
        storage.write(&key, epoch)
    }

    fn get_last_update_storage_key(&self) -> storage::Key {
        self.storage_prefix
            .push(&LAST_UPDATE_SUB_KEY.to_owned())
            .unwrap()
    }

    /// Get the epoch of the most recent update
    pub fn get_last_update<S>(
        &self,
        storage: &S,
    ) -> storage_api::Result<Option<Epoch>>
    where
        S: StorageRead,
    {
        let key = self.get_last_update_storage_key();
        storage.read(&key)
    }

    /// Set the epoch of the most recent update
    pub fn set_last_update<S>(
        &self,
        storage: &mut S,
        current_epoch: Epoch,
    ) -> storage_api::Result<()>
    where
        S: StorageWrite + StorageRead,
    {
        let key = self.get_last_update_storage_key();
        storage.write(&key, current_epoch)
    }
}

impl<Data, FutureEpochs, PastEpochs>
    EpochedDelta<Data, FutureEpochs, PastEpochs>
where
    FutureEpochs: EpochOffset,
    PastEpochs: EpochOffset,
    Data: BorshSerialize
        + BorshDeserialize
        + ops::Add<Output = Data>
        + ops::AddAssign
        + 'static
        + Debug,
{
    /// Open the handle
    pub fn open(key: storage::Key) -> Self {
        Self {
            storage_prefix: key,
            future_epochs: PhantomData,
            past_epochs: PhantomData,
            data: PhantomData,
        }
    }

    /// init at genesis
    pub fn init_at_genesis<S>(
        &self,
        storage: &mut S,
        value: Data,
        current_epoch: Epoch,
    ) -> storage_api::Result<()>
    where
        S: StorageWrite + StorageRead,
    {
        let key = self.get_last_update_storage_key();
        storage.write(&key, current_epoch)?;
        self.set_oldest_epoch(storage, current_epoch)?;
        self.set_at_epoch(storage, value, current_epoch, 0)
    }

    /// Get the delta value at the given epoch
    pub fn get_delta_val<S>(
        &self,
        storage: &S,
        epoch: Epoch,
        _params: &PosParams,
    ) -> storage_api::Result<Option<Data>>
    where
        S: StorageRead,
    {
        self.get_data_handler().get(storage, &epoch)
    }

    /// Get the sum of the delta values up through the given epoch
    pub fn get_sum<S>(
        &self,
        storage: &S,
        epoch: Epoch,
        params: &PosAndGovParams,
    ) -> storage_api::Result<Option<Data>>
    where
        S: StorageRead,
    {
        let last_update = self.get_last_update(storage)?;
        match last_update {
            None => Ok(None),
            Some(last_update) => {
                let data_handler = self.get_data_handler();
                let start_epoch = Self::sub_past_epochs(params, last_update);
                let future_most_epoch =
                    last_update + FutureEpochs::value(params);

                // Epoch can be a lot greater than the epoch where
                // a value is recorded, we check the upper bound
                // epoch of the LazyMap data
                let epoch = std::cmp::min(epoch, future_most_epoch);

                let mut sum: Option<Data> = None;
                for ep in (start_epoch.0)..=(epoch.0) {
                    if let Some(delta) =
                        data_handler.get(storage, &Epoch(ep))?
                    {
                        match sum.as_mut() {
                            Some(sum) => *sum += delta,
                            None => sum = Some(delta),
                        }
                    }
                }
                Ok(sum)
            }
        }
    }

    /// Initialize or set the value at the given epoch offset.
    pub fn set<S>(
        &self,
        storage: &mut S,
        value: Data,
        current_epoch: Epoch,
        offset: u64,
    ) -> storage_api::Result<()>
    where
        S: StorageWrite + StorageRead,
    {
        let params = read_pos_and_gov_params(storage)?;
        self.update_data(storage, &params, current_epoch)?;
        self.set_at_epoch(storage, value, current_epoch, offset)
    }

    fn set_at_epoch<S>(
        &self,
        storage: &mut S,
        value: Data,
        current_epoch: Epoch,
        offset: u64,
    ) -> storage_api::Result<()>
    where
        S: StorageWrite + StorageRead,
    {
        let data_handler = self.get_data_handler();
        let epoch = current_epoch + offset;
        let _prev = data_handler.insert(storage, epoch, value)?;
        Ok(())
    }

    /// Update the data associated with epochs to trim historical data, if
    /// needed. Any value with epoch before the oldest epoch to be kept is
    /// added to the value at the oldest stored epoch that is kept.
    fn update_data<S>(
        &self,
        storage: &mut S,
        params: &PosAndGovParams,
        current_epoch: Epoch,
    ) -> storage_api::Result<()>
    where
        S: StorageWrite + StorageRead,
    {
        let last_update = self.get_last_update(storage)?;
        let oldest_epoch = self.get_oldest_epoch(storage)?;
        if let (Some(last_update), Some(oldest_epoch)) =
            (last_update, oldest_epoch)
        {
            let oldest_to_keep = current_epoch
                .0
                .checked_sub(PastEpochs::value(params))
                .unwrap_or_default();
            if oldest_epoch.0 < oldest_to_keep {
                let diff = oldest_to_keep - oldest_epoch.0;
                // Go through the epochs before the expected oldest epoch and
                // sum them into it
                tracing::debug!(
                    "Trimming data for epoched delta data in epoch \
                     {current_epoch}, last updated at {last_update}."
                );
                let data_handler = self.get_data_handler();
                // Find the sum of values before the new oldest epoch to be kept
                let mut sum: Option<Data> = None;
                for epoch in oldest_epoch.iter_range(diff) {
                    let removed = data_handler.remove(storage, &epoch)?;
                    if let Some(removed) = removed {
                        tracing::debug!(
                            "Removed delta value at epoch {epoch}: {removed:?}"
                        );
                        match sum.as_mut() {
                            Some(sum) => *sum += removed,
                            None => sum = Some(removed),
                        }
                    }
                }
                if let Some(sum) = sum {
                    let new_oldest_epoch =
                        Self::sub_past_epochs(params, current_epoch);
                    let new_oldest_epoch_data =
                        match data_handler.get(storage, &new_oldest_epoch)? {
                            Some(oldest_epoch_data) => oldest_epoch_data + sum,
                            None => sum,
                        };
                    tracing::debug!(
                        "Adding new sum at epoch {new_oldest_epoch}: \
                         {new_oldest_epoch_data:?}"
                    );
                    data_handler.insert(
                        storage,
                        new_oldest_epoch,
                        new_oldest_epoch_data,
                    )?;
                    self.set_oldest_epoch(storage, new_oldest_epoch)?;
                }
                // Update the epoch of the last update to the current epoch
                let key = self.get_last_update_storage_key();
                storage.write(&key, current_epoch)?;
                return Ok(());
            }
        }

        // Set the epoch of the last update to the current epoch
        let key = self.get_last_update_storage_key();
        storage.write(&key, current_epoch)?;

        // If there's no oldest epoch written yet, set it to the current one
        if oldest_epoch.is_none() {
            self.set_oldest_epoch(storage, current_epoch)?;
        }
        Ok(())
    }

    fn get_last_update_storage_key(&self) -> storage::Key {
        self.storage_prefix
            .push(&LAST_UPDATE_SUB_KEY.to_owned())
            .unwrap()
    }

    /// Get the epoch of the most recent update
    pub fn get_last_update<S>(
        &self,
        storage: &S,
    ) -> storage_api::Result<Option<Epoch>>
    where
        S: StorageRead,
    {
        let key = self.get_last_update_storage_key();
        storage.read(&key)
    }

    /// Get handle to the raw LazyMap data
    pub fn get_data_handler(&self) -> LazyMap<Epoch, Data> {
        let key = self
            .storage_prefix
            .push(&LAZY_MAP_SUB_KEY.to_owned())
            .unwrap();
        LazyMap::open(key)
    }

    /// Read all the data into a `HashMap`
    pub fn to_hashmap<S>(
        &self,
        storage: &S,
    ) -> storage_api::Result<HashMap<Epoch, Data>>
    where
        S: StorageRead,
    {
        let handle = self.get_data_handler();
        handle.iter(storage)?.collect()
    }

    fn sub_past_epochs(params: &PosAndGovParams, epoch: Epoch) -> Epoch {
        Epoch(
            epoch
                .0
                .checked_sub(PastEpochs::value(params))
                .unwrap_or_default(),
        )
    }

    fn get_oldest_epoch_storage_key(&self) -> storage::Key {
        self.storage_prefix
            .push(&OLDEST_EPOCH_SUB_KEY.to_owned())
            .unwrap()
    }

    fn get_oldest_epoch<S>(
        &self,
        storage: &S,
    ) -> storage_api::Result<Option<Epoch>>
    where
        S: StorageRead,
    {
        let key = self.get_oldest_epoch_storage_key();
        storage.read(&key)
    }

    fn set_oldest_epoch<S>(
        &self,
        storage: &mut S,
        new_oldest_epoch: Epoch,
    ) -> storage_api::Result<()>
    where
        S: StorageRead + StorageWrite,
    {
        let key = self.get_oldest_epoch_storage_key();
        storage.write(&key, new_oldest_epoch)
    }
}

/// Zero offset
#[derive(
    Debug,
    Clone,
    BorshDeserialize,
    BorshSerialize,
    BorshSchema,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
)]
pub struct OffsetZero;
impl EpochOffset for OffsetZero {
    fn value(_params: &PosAndGovParams) -> u64 {
        0
    }

    fn dyn_offset() -> DynEpochOffset {
        DynEpochOffset::Zero
    }
}

/// Default offset
#[derive(
    Debug,
    Clone,
    BorshDeserialize,
    BorshSerialize,
    BorshSchema,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
)]
pub struct OffsetDefaultNumPastEpochs;
impl EpochOffset for OffsetDefaultNumPastEpochs {
    fn value(_params: &PosAndGovParams) -> u64 {
        DEFAULT_NUM_PAST_EPOCHS
    }

    fn dyn_offset() -> DynEpochOffset {
        DynEpochOffset::DefaultNumPastEpoch
    }
}

/// Offset at pipeline length.
#[derive(
    Debug,
    Clone,
    BorshDeserialize,
    BorshSerialize,
    BorshSchema,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
)]
pub struct OffsetPipelineLen;
impl EpochOffset for OffsetPipelineLen {
    fn value(params: &PosAndGovParams) -> u64 {
        params.pos_params.pipeline_len
    }

    fn dyn_offset() -> DynEpochOffset {
        DynEpochOffset::PipelineLen
    }
}

/// Offset at unbonding length.
#[derive(
    Debug,
    Clone,
    BorshDeserialize,
    BorshSerialize,
    BorshSchema,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
)]
pub struct OffsetUnbondingLen;
impl EpochOffset for OffsetUnbondingLen {
    fn value(params: &PosAndGovParams) -> u64 {
        params.pos_params.unbonding_len
    }

    fn dyn_offset() -> DynEpochOffset {
        DynEpochOffset::UnbondingLen
    }
}

/// Offset at pipeline + unbonding length.
#[derive(
    Debug,
    Clone,
    BorshDeserialize,
    BorshSerialize,
    BorshSchema,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
)]
pub struct OffsetPipelinePlusUnbondingLen;
impl EpochOffset for OffsetPipelinePlusUnbondingLen {
    fn value(params: &PosAndGovParams) -> u64 {
        params.pos_params.pipeline_len + params.pos_params.unbonding_len
    }

    fn dyn_offset() -> DynEpochOffset {
        DynEpochOffset::PipelinePlusUnbondingLen
    }
}

/// Offset at the slash processing delay.
#[derive(
    Debug,
    Clone,
    BorshDeserialize,
    BorshSerialize,
    BorshSchema,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
)]
pub struct OffsetSlashProcessingLen;
impl EpochOffset for OffsetSlashProcessingLen {
    fn value(params: &PosAndGovParams) -> u64 {
        params.pos_params.slash_processing_epoch_offset()
    }

    fn dyn_offset() -> DynEpochOffset {
        DynEpochOffset::SlashProcessingLen
    }
}

/// Maximum offset.
#[derive(
    Debug,
    Clone,
    BorshDeserialize,
    BorshSerialize,
    BorshSchema,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
)]
pub struct OffsetMaxU64;
impl EpochOffset for OffsetMaxU64 {
    fn value(_params: &PosAndGovParams) -> u64 {
        u64::MAX
    }

    fn dyn_offset() -> DynEpochOffset {
        DynEpochOffset::MaxU64
    }
}

/// Offset length dynamic choice.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum DynEpochOffset {
    /// Zero offset
    Zero,
    /// Offset at the const default num past epochs (above)
    DefaultNumPastEpoch,
    /// Offset at pipeline length - 1
    PipelineLenMinusOne,
    /// Offset at pipeline length.
    PipelineLen,
    /// Offset at unbonding length.
    UnbondingLen,
    /// Offset at pipeline + unbonding length.
    PipelinePlusUnbondingLen,
    /// Offset at slash processing delay (unbonding +
    /// cubic_slashing_window + 1).
    SlashProcessingLen,
    /// Offset at the max proposal period
    MaxProposalPeriod,
    /// Offset at the larger of max proposal period or slash processing delay
    MaxProposalPeriodOrSlashProcessingLen,
    /// Offset of the max u64 value
    MaxU64,
}

/// Which offset should be used to set data. The value is read from
/// [`PosParams`].
pub trait EpochOffset:
    Debug + Clone + BorshDeserialize + BorshSerialize + BorshSchema
{
    /// Find the value of a given offset from PoS and Gov parameters.
    fn value(params: &PosAndGovParams) -> u64;
    /// Convert to [`DynEpochOffset`]
    fn dyn_offset() -> DynEpochOffset;
}

#[cfg(test)]
mod test {
    use namada_core::ledger::storage::testing::TestWlStorage;
    use namada_core::types::address::testing::established_address_1;
    use namada_core::types::dec::Dec;
    use namada_core::types::{key, token};
    use test_log::test;

    use super::*;
    use crate::types::GenesisValidator;

    #[test]
    fn test_epoched_data_trimming() -> storage_api::Result<()> {
        let mut s = init_storage()?;

        let key_prefix = storage::Key::parse("test").unwrap();
        let epoched =
            Epoched::<u64, OffsetPipelineLen, OffsetPipelineLen>::open(
                key_prefix,
            );
        let data_handler = epoched.get_data_handler();
        assert!(epoched.get_last_update(&s)?.is_none());
        assert!(epoched.get_oldest_epoch(&s)?.is_none());

        epoched.init_at_genesis(&mut s, 0, Epoch(0))?;
        assert_eq!(epoched.get_last_update(&s)?, Some(Epoch(0)));
        assert_eq!(epoched.get_oldest_epoch(&s)?, Some(Epoch(0)));
        assert_eq!(data_handler.get(&s, &Epoch(0))?, Some(0));

        epoched.set(&mut s, 1, Epoch(0), 0)?;
        assert_eq!(epoched.get_last_update(&s)?, Some(Epoch(0)));
        assert_eq!(epoched.get_oldest_epoch(&s)?, Some(Epoch(0)));
        assert_eq!(data_handler.get(&s, &Epoch(0))?, Some(1));

        epoched.set(&mut s, 2, Epoch(1), 0)?;
        assert_eq!(epoched.get_last_update(&s)?, Some(Epoch(1)));
        assert_eq!(epoched.get_oldest_epoch(&s)?, Some(Epoch(0)));
        assert_eq!(data_handler.get(&s, &Epoch(0))?, Some(1));
        assert_eq!(data_handler.get(&s, &Epoch(1))?, Some(2));

        // Nothing is trimmed yet, oldest kept epoch is 0
        epoched.set(&mut s, 3, Epoch(2), 0)?;
        assert_eq!(epoched.get_last_update(&s)?, Some(Epoch(2)));
        assert_eq!(epoched.get_oldest_epoch(&s)?, Some(Epoch(0)));
        assert_eq!(data_handler.get(&s, &Epoch(0))?, Some(1));
        assert_eq!(data_handler.get(&s, &Epoch(1))?, Some(2));
        assert_eq!(data_handler.get(&s, &Epoch(2))?, Some(3));

        // Epoch 0 should be trimmed now, oldest kept epoch is 1
        epoched.set(&mut s, 4, Epoch(3), 0)?;
        assert_eq!(epoched.get_last_update(&s)?, Some(Epoch(3)));
        assert_eq!(epoched.get_oldest_epoch(&s)?, Some(Epoch(1)));
        assert_eq!(data_handler.get(&s, &Epoch(0))?, None);
        assert_eq!(data_handler.get(&s, &Epoch(1))?, Some(2));
        assert_eq!(data_handler.get(&s, &Epoch(2))?, Some(3));
        assert_eq!(data_handler.get(&s, &Epoch(3))?, Some(4));

        // Anything before epoch 3 should be trimmed
        epoched.set(&mut s, 5, Epoch(5), 0)?;
        assert_eq!(epoched.get_last_update(&s)?, Some(Epoch(5)));
        assert_eq!(epoched.get_oldest_epoch(&s)?, Some(Epoch(3)));
        assert_eq!(data_handler.get(&s, &Epoch(0))?, None);
        assert_eq!(data_handler.get(&s, &Epoch(1))?, None);
        assert_eq!(data_handler.get(&s, &Epoch(2))?, None);
        assert_eq!(data_handler.get(&s, &Epoch(3))?, Some(4));
        assert_eq!(data_handler.get(&s, &Epoch(5))?, Some(5));

        // Anything before epoch 8 should be trimmed
        epoched.set(&mut s, 6, Epoch(10), 0)?;
        assert_eq!(epoched.get_last_update(&s)?, Some(Epoch(10)));
        assert_eq!(epoched.get_oldest_epoch(&s)?, Some(Epoch(8)));
        for epoch in Epoch(0).iter_range(7) {
            assert_eq!(data_handler.get(&s, &epoch)?, None);
        }
        // The value from the latest epoch 5 is assigned to epoch 8
        assert_eq!(data_handler.get(&s, &Epoch(8))?, Some(5));
        assert_eq!(data_handler.get(&s, &Epoch(9))?, None);
        assert_eq!(data_handler.get(&s, &Epoch(10))?, Some(6));

        Ok(())
    }

    #[test]
    fn test_epoched_without_data_trimming() -> storage_api::Result<()> {
        let mut s = init_storage()?;

        let key_prefix = storage::Key::parse("test").unwrap();
        let epoched =
            Epoched::<u64, OffsetPipelineLen, OffsetMaxU64>::open(key_prefix);
        let data_handler = epoched.get_data_handler();
        assert!(epoched.get_last_update(&s)?.is_none());
        assert!(epoched.get_oldest_epoch(&s)?.is_none());

        epoched.init_at_genesis(&mut s, 0, Epoch(0))?;
        assert_eq!(epoched.get_last_update(&s)?, Some(Epoch(0)));
        assert_eq!(epoched.get_oldest_epoch(&s)?, Some(Epoch(0)));
        assert_eq!(data_handler.get(&s, &Epoch(0))?, Some(0));

        epoched.set(&mut s, 1, Epoch(0), 0)?;
        assert_eq!(epoched.get_last_update(&s)?, Some(Epoch(0)));
        assert_eq!(epoched.get_oldest_epoch(&s)?, Some(Epoch(0)));
        assert_eq!(data_handler.get(&s, &Epoch(0))?, Some(1));

        epoched.set(&mut s, 2, Epoch(1), 0)?;
        assert_eq!(epoched.get_last_update(&s)?, Some(Epoch(1)));
        assert_eq!(epoched.get_oldest_epoch(&s)?, Some(Epoch(0)));
        assert_eq!(data_handler.get(&s, &Epoch(0))?, Some(1));
        assert_eq!(data_handler.get(&s, &Epoch(1))?, Some(2));

        epoched.set(&mut s, 3, Epoch(2), 0)?;
        assert_eq!(epoched.get_last_update(&s)?, Some(Epoch(2)));
        assert_eq!(epoched.get_oldest_epoch(&s)?, Some(Epoch(0)));
        assert_eq!(data_handler.get(&s, &Epoch(0))?, Some(1));
        assert_eq!(data_handler.get(&s, &Epoch(1))?, Some(2));
        assert_eq!(data_handler.get(&s, &Epoch(2))?, Some(3));

        epoched.set(&mut s, 4, Epoch(3), 0)?;
        assert_eq!(epoched.get_last_update(&s)?, Some(Epoch(3)));
        assert_eq!(epoched.get_oldest_epoch(&s)?, Some(Epoch(0)));
        assert_eq!(data_handler.get(&s, &Epoch(0))?, Some(1));
        assert_eq!(data_handler.get(&s, &Epoch(1))?, Some(2));
        assert_eq!(data_handler.get(&s, &Epoch(2))?, Some(3));
        assert_eq!(data_handler.get(&s, &Epoch(3))?, Some(4));

        epoched.set(&mut s, 5, Epoch(5), 0)?;
        assert_eq!(epoched.get_last_update(&s)?, Some(Epoch(5)));
        assert_eq!(epoched.get_oldest_epoch(&s)?, Some(Epoch(0)));
        assert_eq!(data_handler.get(&s, &Epoch(0))?, Some(1));
        assert_eq!(data_handler.get(&s, &Epoch(1))?, Some(2));
        assert_eq!(data_handler.get(&s, &Epoch(2))?, Some(3));
        assert_eq!(data_handler.get(&s, &Epoch(3))?, Some(4));
        assert_eq!(data_handler.get(&s, &Epoch(5))?, Some(5));

        epoched.set(&mut s, 6, Epoch(10), 0)?;
        assert_eq!(epoched.get_last_update(&s)?, Some(Epoch(10)));
        assert_eq!(epoched.get_oldest_epoch(&s)?, Some(Epoch(0)));
        assert_eq!(data_handler.get(&s, &Epoch(0))?, Some(1));
        assert_eq!(data_handler.get(&s, &Epoch(1))?, Some(2));
        assert_eq!(data_handler.get(&s, &Epoch(2))?, Some(3));
        assert_eq!(data_handler.get(&s, &Epoch(3))?, Some(4));
        assert_eq!(data_handler.get(&s, &Epoch(5))?, Some(5));
        assert_eq!(data_handler.get(&s, &Epoch(6))?, None);
        assert_eq!(data_handler.get(&s, &Epoch(7))?, None);
        assert_eq!(data_handler.get(&s, &Epoch(8))?, None);
        assert_eq!(data_handler.get(&s, &Epoch(9))?, None);
        assert_eq!(data_handler.get(&s, &Epoch(10))?, Some(6));

        Ok(())
    }

    #[test]
    fn test_epoched_delta_data_trimming() -> storage_api::Result<()> {
        let mut s = init_storage()?;

        let key_prefix = storage::Key::parse("test").unwrap();
        let epoched =
            EpochedDelta::<u64, OffsetPipelineLen, OffsetPipelineLen>::open(
                key_prefix,
            );
        let data_handler = epoched.get_data_handler();
        assert!(epoched.get_last_update(&s)?.is_none());
        assert!(epoched.get_oldest_epoch(&s)?.is_none());

        epoched.init_at_genesis(&mut s, 0, Epoch(0))?;
        assert_eq!(epoched.get_last_update(&s)?, Some(Epoch(0)));
        assert_eq!(epoched.get_oldest_epoch(&s)?, Some(Epoch(0)));
        assert_eq!(data_handler.get(&s, &Epoch(0))?, Some(0));

        epoched.set(&mut s, 1, Epoch(0), 0)?;
        assert_eq!(epoched.get_last_update(&s)?, Some(Epoch(0)));
        assert_eq!(epoched.get_oldest_epoch(&s)?, Some(Epoch(0)));
        assert_eq!(data_handler.get(&s, &Epoch(0))?, Some(1));

        epoched.set(&mut s, 2, Epoch(1), 0)?;
        assert_eq!(epoched.get_last_update(&s)?, Some(Epoch(1)));
        assert_eq!(epoched.get_oldest_epoch(&s)?, Some(Epoch(0)));
        assert_eq!(data_handler.get(&s, &Epoch(0))?, Some(1));
        assert_eq!(data_handler.get(&s, &Epoch(1))?, Some(2));

        // Nothing is trimmed yet, oldest kept epoch is 0
        epoched.set(&mut s, 3, Epoch(2), 0)?;
        assert_eq!(epoched.get_last_update(&s)?, Some(Epoch(2)));
        assert_eq!(epoched.get_oldest_epoch(&s)?, Some(Epoch(0)));
        assert_eq!(data_handler.get(&s, &Epoch(0))?, Some(1));
        assert_eq!(data_handler.get(&s, &Epoch(1))?, Some(2));
        assert_eq!(data_handler.get(&s, &Epoch(2))?, Some(3));

        // Epoch 0 should be trimmed now, oldest kept epoch is 1
        epoched.set(&mut s, 4, Epoch(3), 0)?;
        assert_eq!(epoched.get_last_update(&s)?, Some(Epoch(3)));
        assert_eq!(epoched.get_oldest_epoch(&s)?, Some(Epoch(1)));
        assert_eq!(data_handler.get(&s, &Epoch(0))?, None);
        // The value from epoch 0 should be added to epoch 1
        assert_eq!(data_handler.get(&s, &Epoch(1))?, Some(3));
        assert_eq!(data_handler.get(&s, &Epoch(2))?, Some(3));
        assert_eq!(data_handler.get(&s, &Epoch(3))?, Some(4));

        // Anything before epoch 3 should be trimmed
        epoched.set(&mut s, 5, Epoch(5), 0)?;
        assert_eq!(epoched.get_last_update(&s)?, Some(Epoch(5)));
        assert_eq!(epoched.get_oldest_epoch(&s)?, Some(Epoch(3)));
        assert_eq!(data_handler.get(&s, &Epoch(0))?, None);
        assert_eq!(data_handler.get(&s, &Epoch(1))?, None);
        assert_eq!(data_handler.get(&s, &Epoch(2))?, None);
        // The values from epoch 1 and 2 should be added to epoch 3
        assert_eq!(data_handler.get(&s, &Epoch(3))?, Some(10));
        assert_eq!(data_handler.get(&s, &Epoch(5))?, Some(5));

        // Anything before epoch 8 should be trimmed
        epoched.set(&mut s, 6, Epoch(10), 0)?;
        assert_eq!(epoched.get_last_update(&s)?, Some(Epoch(10)));
        assert_eq!(epoched.get_oldest_epoch(&s)?, Some(Epoch(8)));
        for epoch in Epoch(0).iter_range(7) {
            assert_eq!(data_handler.get(&s, &epoch)?, None);
        }
        // The values from epoch 3 and 5 should be added to epoch 3
        assert_eq!(data_handler.get(&s, &Epoch(8))?, Some(15));
        assert_eq!(data_handler.get(&s, &Epoch(9))?, None);
        assert_eq!(data_handler.get(&s, &Epoch(10))?, Some(6));

        Ok(())
    }

    #[test]
    fn test_epoched_delta_without_data_trimming() -> storage_api::Result<()> {
        let mut s = init_storage()?;

        // Nothing should ever get trimmed
        let key_prefix = storage::Key::parse("test").unwrap();
        let epoched =
            EpochedDelta::<u64, OffsetPipelineLen, OffsetMaxU64>::open(
                key_prefix,
            );
        let data_handler = epoched.get_data_handler();
        assert!(epoched.get_last_update(&s)?.is_none());
        assert!(epoched.get_oldest_epoch(&s)?.is_none());

        epoched.init_at_genesis(&mut s, 0, Epoch(0))?;
        assert_eq!(epoched.get_last_update(&s)?, Some(Epoch(0)));
        assert_eq!(epoched.get_oldest_epoch(&s)?, Some(Epoch(0)));
        assert_eq!(data_handler.get(&s, &Epoch(0))?, Some(0));

        epoched.set(&mut s, 1, Epoch(0), 0)?;
        assert_eq!(epoched.get_last_update(&s)?, Some(Epoch(0)));
        assert_eq!(epoched.get_oldest_epoch(&s)?, Some(Epoch(0)));
        assert_eq!(data_handler.get(&s, &Epoch(0))?, Some(1));

        epoched.set(&mut s, 2, Epoch(1), 0)?;
        assert_eq!(epoched.get_last_update(&s)?, Some(Epoch(1)));
        assert_eq!(epoched.get_oldest_epoch(&s)?, Some(Epoch(0)));
        assert_eq!(data_handler.get(&s, &Epoch(0))?, Some(1));
        assert_eq!(data_handler.get(&s, &Epoch(1))?, Some(2));

        epoched.set(&mut s, 3, Epoch(2), 0)?;
        assert_eq!(epoched.get_last_update(&s)?, Some(Epoch(2)));
        assert_eq!(epoched.get_oldest_epoch(&s)?, Some(Epoch(0)));
        assert_eq!(data_handler.get(&s, &Epoch(0))?, Some(1));
        assert_eq!(data_handler.get(&s, &Epoch(1))?, Some(2));
        assert_eq!(data_handler.get(&s, &Epoch(2))?, Some(3));

        epoched.set(&mut s, 4, Epoch(3), 0)?;
        assert_eq!(epoched.get_last_update(&s)?, Some(Epoch(3)));
        assert_eq!(epoched.get_oldest_epoch(&s)?, Some(Epoch(0)));
        assert_eq!(data_handler.get(&s, &Epoch(0))?, Some(1));
        assert_eq!(data_handler.get(&s, &Epoch(1))?, Some(2));
        assert_eq!(data_handler.get(&s, &Epoch(2))?, Some(3));
        assert_eq!(data_handler.get(&s, &Epoch(3))?, Some(4));

        epoched.set(&mut s, 5, Epoch(5), 0)?;
        assert_eq!(epoched.get_last_update(&s)?, Some(Epoch(5)));
        assert_eq!(epoched.get_oldest_epoch(&s)?, Some(Epoch(0)));
        assert_eq!(data_handler.get(&s, &Epoch(0))?, Some(1));
        assert_eq!(data_handler.get(&s, &Epoch(1))?, Some(2));
        assert_eq!(data_handler.get(&s, &Epoch(2))?, Some(3));
        assert_eq!(data_handler.get(&s, &Epoch(3))?, Some(4));
        assert_eq!(data_handler.get(&s, &Epoch(5))?, Some(5));

        epoched.set(&mut s, 6, Epoch(10), 0)?;
        assert_eq!(epoched.get_last_update(&s)?, Some(Epoch(10)));
        assert_eq!(epoched.get_oldest_epoch(&s)?, Some(Epoch(0)));
        assert_eq!(data_handler.get(&s, &Epoch(0))?, Some(1));
        assert_eq!(data_handler.get(&s, &Epoch(1))?, Some(2));
        assert_eq!(data_handler.get(&s, &Epoch(2))?, Some(3));
        assert_eq!(data_handler.get(&s, &Epoch(3))?, Some(4));
        assert_eq!(data_handler.get(&s, &Epoch(5))?, Some(5));
        assert_eq!(data_handler.get(&s, &Epoch(6))?, None);
        assert_eq!(data_handler.get(&s, &Epoch(7))?, None);
        assert_eq!(data_handler.get(&s, &Epoch(8))?, None);
        assert_eq!(data_handler.get(&s, &Epoch(9))?, None);
        assert_eq!(data_handler.get(&s, &Epoch(10))?, Some(6));

        Ok(())
    }

    fn init_storage() -> storage_api::Result<TestWlStorage> {
        let mut s = TestWlStorage::default();
        crate::init_genesis(
            &mut s,
            &PosParams::default(),
            [GenesisValidator {
                address: established_address_1(),
                tokens: token::Amount::native_whole(1_000),
                consensus_key: key::testing::keypair_1().to_public(),
                eth_hot_key: key::testing::keypair_3().to_public(),
                eth_cold_key: key::testing::keypair_3().to_public(),
                commission_rate: Dec::new(1, 1).expect("Dec creation failed"),
                max_commission_rate_change: Dec::new(1, 1)
                    .expect("Dec creation failed"),
            }]
            .into_iter(),
            Epoch::default(),
        )?;
        Ok(s)
    }
}
