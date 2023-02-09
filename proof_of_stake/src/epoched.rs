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

use crate::parameters::PosParams;

/// Sub-key holding a lazy map in storage
pub const LAZY_MAP_SUB_KEY: &str = "lazy_map";
/// Sub-key for an epoched data structure's last (most recent) epoch of update
pub const LAST_UPDATE_SUB_KEY: &str = "last_update";

/// Discrete epoched data handle
pub struct Epoched<
    Data,
    FutureEpochs,
    const NUM_PAST_EPOCHS: u64 = 0,
    SON = collections::Simple,
> {
    storage_prefix: storage::Key,
    future_epochs: PhantomData<FutureEpochs>,
    data: PhantomData<Data>,
    phantom_son: PhantomData<SON>,
}

/// Discrete epoched data handle with nested lazy structure
pub type NestedEpoched<Data, FutureEpochs, const NUM_PAST_EPOCHS: u64 = 0> =
    Epoched<Data, FutureEpochs, NUM_PAST_EPOCHS, collections::Nested>;

/// Delta epoched data handle
pub struct EpochedDelta<Data, FutureEpochs, const NUM_PAST_EPOCHS: u64> {
    storage_prefix: storage::Key,
    future_epochs: PhantomData<FutureEpochs>,
    data: PhantomData<Data>,
}

impl<Data, FutureEpochs, const NUM_PAST_EPOCHS: u64, SON>
    Epoched<Data, FutureEpochs, NUM_PAST_EPOCHS, SON>
where
    FutureEpochs: EpochOffset,
{
    /// Open the handle
    pub fn open(key: storage::Key) -> Self {
        Self {
            storage_prefix: key,
            future_epochs: PhantomData,
            data: PhantomData,
            phantom_son: PhantomData,
        }
    }

    /// Return the number of past epochs to keep data for
    pub fn get_num_past_epochs() -> u64 {
        NUM_PAST_EPOCHS
    }
}

impl<Data, FutureEpochs, const NUM_PAST_EPOCHS: u64>
    Epoched<Data, FutureEpochs, NUM_PAST_EPOCHS>
where
    FutureEpochs: EpochOffset,
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
        S: StorageWrite + StorageRead,
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
                                && epoch > Self::sub_past_epochs(last_update)
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

    /// Set the value at the given epoch offset.
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
        S: StorageWrite + StorageRead,
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
        S: StorageWrite + StorageRead,
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
            storage.write(&key, current_epoch)?;
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

    fn sub_past_epochs(epoch: Epoch) -> Epoch {
        Epoch(epoch.0.checked_sub(NUM_PAST_EPOCHS).unwrap_or_default())
    }
}

impl<Data, FutureEpochs, const NUM_PAST_EPOCHS: u64>
    Epoched<Data, FutureEpochs, NUM_PAST_EPOCHS, collections::Nested>
where
    FutureEpochs: EpochOffset,
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

    /// TODO
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

    /// TODO
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

    /// TODO
    pub fn sub_past_epochs(epoch: Epoch) -> Epoch {
        Epoch(epoch.0.checked_sub(NUM_PAST_EPOCHS).unwrap_or_default())
    }

    // pub fn get_inner_by_epoch(&self) -> storage_api::Result<Data> {}

    // TODO: we may need an update_data() method, figure out when it should be
    // called (in at()?)
}

// impl<K, V, SON, FutureEpochs, const NUM_PAST_EPOCHS: u64>
//     Epoched<
//         LazyMap<K, V, SON>,
//         FutureEpochs,
//         NUM_PAST_EPOCHS,
//         collections::Nested,
//     >
// where
//     FutureEpochs: EpochOffset,
// {
//     pub fn get_inner_by_epoch(&self, epoch: &Epoch) -> LazyMap<K, V, SON> {
//         self.at()
//     }
// }

impl<Data, FutureEpochs, const NUM_PAST_EPOCHS: u64>
    EpochedDelta<Data, FutureEpochs, NUM_PAST_EPOCHS>
where
    FutureEpochs: EpochOffset,
    Data: BorshSerialize
        + BorshDeserialize
        + ops::Add<Output = Data>
        + 'static
        + Debug,
{
    /// Open the handle
    pub fn open(key: storage::Key) -> Self {
        Self {
            storage_prefix: key,
            future_epochs: PhantomData,
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
        S: StorageWrite + StorageRead,
    {
        let key = self.get_last_update_storage_key();
        storage.write(&key, current_epoch)?;

        self.set_at_epoch(storage, value, current_epoch, offset)
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
        // let last_update = self.get_last_update(storage)?;
        // match last_update {
        //     None => Ok(None),
        //     Some(last_update) => {
        //         let data_handler = self.get_data_handler();
        //         let future_most_epoch =
        //             last_update + FutureEpochs::value(params);
        //         // Epoch can be a lot greater than the epoch where
        //         // a value is recorded, we check the upper bound
        //         // epoch of the LazyMap data
        //         let mut epoch = std::cmp::min(epoch, future_most_epoch);
        //         loop {
        //             let res = data_handler.get(storage, &epoch)?;
        //             match res {
        //                 Some(_) => return Ok(res),
        //                 None => {
        //                     if epoch.0 > 0
        //                         && epoch > Self::sub_past_epochs(last_update)
        //                     {
        //                         epoch = Epoch(epoch.0 - 1);
        //                     } else {
        //                         return Ok(None);
        //                     }
        //                 }
        //             }
        //         }
        //     }
        // }
    }

    /// Get the sum of the delta values up through the given epoch
    pub fn get_sum<S>(
        &self,
        storage: &S,
        epoch: Epoch,
        params: &PosParams,
    ) -> storage_api::Result<Option<Data>>
    where
        S: StorageRead,
    {
        // TODO: oddly failing to do correctly with iter over
        // self.get_data_handler() for some reason (it only finds the
        // first entry in iteration then None afterward). Figure
        // this out!!!

        // println!("GET_SUM AT EPOCH {}", epoch.clone());
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
                let epoch = std::cmp::min(epoch, future_most_epoch);
                let mut sum: Option<Data> = None;

                // ! BELOW IS WHAT IS DESIRED IF ITERATION IS WORKING !
                // for next in data_handler.iter(storage).unwrap() {
                //     match dbg!((&mut sum, next)) {
                //         (Some(_), Ok((next_epoch, next_val))) => {
                //             if next_epoch > epoch {
                //                 return Ok(sum);
                //             } else {
                //                 sum = sum.map(|cur_sum| cur_sum + next_val)
                //             }
                //         }
                //         (None, Ok((next_epoch, next_val))) => {
                //             if epoch < next_epoch {
                //                 return Ok(None);
                //             } else {
                //                 sum = Some(next_val)
                //             }
                //         }
                //         (Some(_), Err(_)) => return Ok(sum),
                //         // perhaps elaborate with an error
                //         _ => return Ok(None),
                //     };
                // }

                // THIS IS THE HACKY METHOD UNTIL I FIGURE OUT WTF GOING ON WITH
                // THE ITER
                let start_epoch = Self::sub_past_epochs(last_update);
                // println!("GETTING SUM OF DELTAS");
                for ep in (start_epoch.0)..=(epoch.0) {
                    // println!("epoch {}", ep);

                    if let Some(val) = data_handler.get(storage, &Epoch(ep))? {
                        if sum.is_none() {
                            sum = Some(val);
                        } else {
                            sum = sum.map(|cur_sum| cur_sum + val);
                        }
                    }
                    // dbg!(&sum);
                }
                Ok(sum)
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
        S: StorageWrite + StorageRead,
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
        S: StorageWrite + StorageRead,
    {
        let data_handler = self.get_data_handler();
        let epoch = current_epoch + offset;
        let _prev = data_handler.insert(storage, epoch, value)?;
        Ok(())
    }

    /// TODO: maybe better description
    /// Update the data associated with epochs, if needed. Any key-value with
    /// epoch before the oldest stored epoch is added to the key-value with the
    /// oldest stored epoch that is kept. If the oldest stored epoch is not
    /// already associated with some value, the latest value from the
    /// dropped values, if any, is associated with it.
    fn update_data<S>(
        &self,
        storage: &mut S,
        current_epoch: Epoch,
    ) -> storage_api::Result<()>
    where
        S: StorageWrite + StorageRead,
    {
        let last_update = self.get_last_update(storage)?;
        if let Some(last_update) = last_update {
            let expected_oldest_epoch = Self::sub_past_epochs(current_epoch);
            if expected_oldest_epoch != last_update {
                // dbg!(last_update, expected_oldest_epoch, current_epoch);
                let diff = expected_oldest_epoch
                    .0
                    .checked_sub(last_update.0)
                    .unwrap_or_default();
                let data_handler = self.get_data_handler();
                let mut new_oldest_value: Option<Data> = None;
                for offset in 1..diff + 1 {
                    let old = data_handler.remove(
                        storage,
                        &Epoch(expected_oldest_epoch.0 - offset),
                    )?;
                    if let Some(old) = old {
                        match new_oldest_value {
                            Some(latest) => {
                                new_oldest_value = Some(latest + old)
                            }
                            None => new_oldest_value = Some(old),
                        }
                    }
                }
                if let Some(new_oldest_value) = new_oldest_value {
                    // TODO we can add `contains_key` to LazyMap
                    if data_handler
                        .get(storage, &expected_oldest_epoch)?
                        .is_none()
                    {
                        data_handler.insert(
                            storage,
                            expected_oldest_epoch,
                            new_oldest_value,
                        )?;
                    }
                }
            }
        }
        let key = self.get_last_update_storage_key();
        storage.write(&key, current_epoch)?;
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
    /// Offset at pipeline length - 1
    PipelineLenMinusOne,
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

// mod test {
// use namada_core::ledger::storage::testing::TestStorage;
// use namada_core::types::address::{self, Address};
// use namada_core::types::storage::Key;
//
// use super::{
// storage, storage_api, Epoch, LazyMap, NestedEpoched, NestedMap,
// OffsetPipelineLen,
// };
//
// #[test]
// fn testing_epoched_new() -> storage_api::Result<()> {
// let mut storage = TestStorage::default();
//
// let key1 = storage::Key::parse("test_nested1").unwrap();
// let nested1 =
// NestedEpoched::<LazyMap<Address, u64>, OffsetPipelineLen>::open(
// key1,
// );
// nested1.init(&mut storage, Epoch(0))?;
//
// let key2 = storage::Key::parse("test_nested2").unwrap();
// let nested2 = NestedEpoched::<
// NestedMap<u64, LazyMap<u64, Address>>,
// OffsetPipelineLen,
// >::open(key2);
// nested2.init(&mut storage, Epoch(0))?;
//
// dbg!(&nested1.get_last_update_storage_key());
// dbg!(&nested1.get_last_update(&storage));
//
// nested1.at(&Epoch(0)).insert(
// &mut storage,
// address::testing::established_address_1(),
// 1432,
// )?;
// dbg!(&nested1.at(&Epoch(0)).iter(&mut storage)?.next());
// dbg!(&nested1.at(&Epoch(1)).iter(&mut storage)?.next());
//
// nested2.at(&Epoch(0)).at(&100).insert(
// &mut storage,
// 1,
// address::testing::established_address_2(),
// )?;
// dbg!(&nested2.at(&Epoch(0)).iter(&mut storage)?.next());
// dbg!(&nested2.at(&Epoch(1)).iter(&mut storage)?.next());
//
// dbg!(&nested_epoched.get_epoch_key(&Epoch::from(0)));
//
// let epoch = Epoch::from(0);
// let addr = address::testing::established_address_1();
// let amount: u64 = 234235;
//
// nested_epoched
//     .at(&epoch)
//     .insert(&mut storage, addr.clone(), amount)?;
//
// let epoch = epoch + 3_u64;
// nested_epoched.at(&epoch).insert(
//     &mut storage,
//     addr.clone(),
//     999_u64,
// )?;
//
// dbg!(nested_epoched.contains_epoch(&storage, &Epoch::from(0))?);
// dbg!(
//     nested_epoched
//         .get_data_handler()
//         .get_data_key(&Epoch::from(3))
// );
// dbg!(nested_epoched.contains_epoch(&storage, &Epoch::from(3))?);
// dbg!(
//     nested_epoched
//         .at(&Epoch::from(0))
//         .get(&storage, &addr.clone())?
// );
// dbg!(
//     nested_epoched
//         .at(&Epoch::from(3))
//         .get(&storage, &addr.clone())?
// );
// dbg!(nested_epoched.at(&Epoch::from(3)).get_data_key(&addr));
//
// Ok(())
// }
// }
