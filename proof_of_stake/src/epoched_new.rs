//! [`Epoched`] and [`EpochedDelta`] are structures for data that is set for
//! future (and possibly past) epochs.

use std::fmt::Debug;
use std::marker::PhantomData;

use borsh::{BorshDeserialize, BorshSchema, BorshSerialize};
use namada_core::ledger::storage_api;
use namada_core::ledger::storage_api::collections::lazy_map::LazyMap;
use namada_core::ledger::storage_api::collections::LazyCollection;
use namada_core::ledger::storage_api::{StorageRead, StorageWrite};
use namada_core::types::storage::{self, Epoch};

use crate::parameters::PosParams;

/// Discrete epoched data handle
pub struct Epoched<Data, FutureEpochs, const NUM_PAST_EPOCHS: u64> {
    storage_prefix: storage::Key,
    future_epochs: PhantomData<FutureEpochs>,
    data: PhantomData<Data>,
}

impl<Data, FutureEpochs, const NUM_PAST_EPOCHS: u64>
    Epoched<Data, FutureEpochs, NUM_PAST_EPOCHS>
where
    FutureEpochs: EpochOffset,
    Data: BorshSerialize + BorshDeserialize + 'static + Debug,
{
    /// Open the handle
    pub fn open(key: storage::Key) -> Self {
        Self {
            storage_prefix: key,
            future_epochs: PhantomData,
            data: PhantomData,
        }
    }

    /// Initialize new epoched data. Sets the head to the given value.
    /// This should only be used at genesis.
    pub fn init_at_genesis<S>(
        &self,
        storage: &mut S,
        value: Data,
        current_epoch: Epoch,
    ) -> storage_api::Result<()>
    where
        S: StorageWrite + for<'iter> StorageRead<'iter>,
    {
        self.init(storage, value, current_epoch, 0)
    }

    /// Initialize new data at the given epoch offset.
    pub fn init<S>(
        &self,
        storage: &mut S,
        value: Data,
        current_epoch: Epoch,
        offset: u64,
    ) -> storage_api::Result<()>
    where
        S: StorageWrite + for<'iter> StorageRead<'iter>,
    {
        let key = self.get_last_update_storage_key();
        storage.write(&key, current_epoch)?;

        self.set_at_epoch(storage, value, current_epoch, offset)
    }

    /// Find the value for the given epoch or a nearest epoch before it.
    pub fn get<S>(
        &self,
        storage: &S,
        epoch: Epoch,
        params: &PosParams,
    ) -> storage_api::Result<Option<Data>>
    where
        S: for<'iter> StorageRead<'iter>,
    {
        let last_update = self.get_last_update(storage)?;
        match last_update {
            None => return Ok(None),
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
                            if epoch.0 > 1
                                && epoch > Self::sub_past_epochs(last_update)
                            {
                                epoch = Epoch(epoch.0 - 1)
                            } else {
                                return Ok(None);
                            }
                        }
                    }
                }
            }
        }
    }

    /// Set the value at the given epoch offset.
    pub fn set<S>(
        &self,
        storage: &mut S,
        value: Data,
        current_epoch: Epoch,
        offset: u64,
    ) -> storage_api::Result<()>
    where
        S: StorageWrite + for<'iter> StorageRead<'iter>,
    {
        self.update_data(storage, current_epoch)?;
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
        S: StorageWrite + for<'iter> StorageRead<'iter>,
    {
        let data_handler = self.get_data_handler();
        let epoch = current_epoch + offset;
        let _prev = data_handler.insert(storage, epoch, value)?;
        Ok(())
    }

    /// Update the data associated with epochs, if needed. Any key-value with
    /// epoch before the oldest stored epoch is dropped. If the oldest
    /// stored epoch is not already associated with some value, the latest
    /// value from the dropped values, if any, is associated with it.
    fn update_data<S>(
        &self,
        storage: &mut S,
        current_epoch: Epoch,
    ) -> storage_api::Result<()>
    where
        S: StorageWrite + for<'iter> StorageRead<'iter>,
    {
        let last_update = self.get_last_update(storage)?;
        if let Some(last_update) = last_update {
            let expected_epoch = Self::sub_past_epochs(current_epoch);
            if expected_epoch == last_update {
                return Ok(());
            } else {
                let diff = expected_epoch.0 - last_update.0;
                let data_handler = self.get_data_handler();
                let mut latest_value: Option<Data> = None;
                for offset in 1..diff + 1 {
                    let old = data_handler
                        .remove(storage, &Epoch(expected_epoch.0 - offset))?;
                    if old.is_some() && latest_value.is_none() {
                        latest_value = old;
                    }
                }
                if let Some(latest_value) = latest_value {
                    // TODO we can add `contains_key` to LazyMap
                    if data_handler.get(storage, &expected_epoch)?.is_none() {
                        data_handler.insert(
                            storage,
                            expected_epoch,
                            latest_value,
                        )?;
                    }
                }
            }
            let key = self.get_last_update_storage_key();
            storage.write(&key, expected_epoch)?;
        }
        Ok(())
    }

    fn get_last_update_storage_key(&self) -> storage::Key {
        self.storage_prefix.push(&"last_update".to_owned()).unwrap()
    }

    fn get_last_update<S>(
        &self,
        storage: &S,
    ) -> storage_api::Result<Option<Epoch>>
    where
        S: for<'iter> StorageRead<'iter>,
    {
        let key = self.get_last_update_storage_key();
        storage.read(&key)
    }

    fn get_data_handler(&self) -> LazyMap<Epoch, Data> {
        let key = self.storage_prefix.push(&"data".to_owned()).unwrap();
        LazyMap::open(key)
    }

    fn sub_past_epochs(epoch: Epoch) -> Epoch {
        Epoch(epoch.0.checked_sub(NUM_PAST_EPOCHS).unwrap_or_default())
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
    fn value(params: &PosParams) -> u64 {
        params.pipeline_len
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
    fn value(params: &PosParams) -> u64 {
        params.unbonding_len
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
    fn value(params: &PosParams) -> u64 {
        params.pipeline_len + params.unbonding_len
    }

    fn dyn_offset() -> DynEpochOffset {
        DynEpochOffset::PipelinePlusUnbondingLen
    }
}

/// Offset length dynamic choice.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum DynEpochOffset {
    /// Offset at pipeline length.
    PipelineLen,
    /// Offset at unbonding length.
    UnbondingLen,
    /// Offset at pipeline + unbonding length.
    PipelinePlusUnbondingLen,
}

/// Which offset should be used to set data. The value is read from
/// [`PosParams`].
pub trait EpochOffset:
    Debug + Clone + BorshDeserialize + BorshSerialize + BorshSchema
{
    /// Find the value of a given offset from PoS parameters.
    fn value(params: &PosParams) -> u64;
    /// Convert to [`DynEpochOffset`]
    fn dyn_offset() -> DynEpochOffset;
}
