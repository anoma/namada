use borsh::{BorshDeserialize, BorshSerialize};
use eyre::{Result, WrapErr};
use namada_core::ledger::storage::{
    DBIter, PrefixIter, StorageHasher, WlStorage, DB,
};
use namada_core::ledger::storage_api::{StorageRead, StorageWrite};
use namada_core::types::storage::Key;
use namada_core::types::voting_power::FractionalVotingPower;

use super::{Tally, Votes};
use crate::storage::vote_tallies;

pub fn write<D, H, T>(
    wl_storage: &mut WlStorage<D, H>,
    keys: &vote_tallies::Keys<T>,
    body: &T,
    tally: &Tally,
    already_present: bool,
) -> Result<()>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
    T: BorshSerialize,
{
    wl_storage.write_bytes(&keys.body(), &body.try_to_vec()?)?;
    wl_storage.write_bytes(&keys.seen(), &tally.seen.try_to_vec()?)?;
    wl_storage.write_bytes(&keys.seen_by(), &tally.seen_by.try_to_vec()?)?;
    wl_storage
        .write_bytes(&keys.voting_power(), &tally.voting_power.try_to_vec()?)?;
    if !already_present {
        // add the current epoch for the inserted event
        wl_storage.write_bytes(
            &keys.voting_started_epoch(),
            &wl_storage.storage.get_current_epoch().0.try_to_vec()?,
        )?;
    }
    Ok(())
}

pub fn delete<D, H, T>(
    wl_storage: &mut WlStorage<D, H>,
    keys: &vote_tallies::Keys<T>,
) -> Result<()>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
    T: BorshSerialize,
{
    wl_storage.delete(&keys.body())?;
    wl_storage.delete(&keys.seen())?;
    wl_storage.delete(&keys.seen_by())?;
    wl_storage.delete(&keys.voting_power())?;
    wl_storage.delete(&keys.voting_started_epoch())?;
    Ok(())
}

pub fn read<D, H, T>(
    wl_storage: &WlStorage<D, H>,
    keys: &vote_tallies::Keys<T>,
) -> Result<Tally>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    let seen: bool = super::read::value(wl_storage, &keys.seen())?;
    let seen_by: Votes = super::read::value(wl_storage, &keys.seen_by())?;
    let voting_power: FractionalVotingPower =
        super::read::value(wl_storage, &keys.voting_power())?;

    Ok(Tally {
        voting_power,
        seen_by,
        seen,
    })
}

pub fn iter_prefix<'a, D, H>(
    wl_storage: &'a WlStorage<D, H>,
    prefix: &Key,
) -> Result<PrefixIter<'a, D>>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    wl_storage
        .iter_prefix(prefix)
        .context("Failed to iterate over the given storage prefix")
}

#[inline]
pub fn read_body<D, H, T>(
    wl_storage: &WlStorage<D, H>,
    keys: &vote_tallies::Keys<T>,
) -> Result<T>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
    T: BorshDeserialize,
{
    super::read::value(wl_storage, &keys.body())
}

#[inline]
pub fn maybe_read_seen<D, H, T>(
    wl_storage: &WlStorage<D, H>,
    keys: &vote_tallies::Keys<T>,
) -> Result<Option<bool>>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
    T: BorshDeserialize,
{
    super::read::maybe_value(wl_storage, &keys.seen())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use namada_core::ledger::storage::testing::TestWlStorage;
    use namada_core::types::address;
    use namada_core::types::ethereum_events::EthereumEvent;
    use namada_core::types::voting_power::FractionalVotingPower;

    use super::*;

    #[test]
    fn test_write_tally() {
        let mut wl_storage = TestWlStorage::default();
        let event = EthereumEvent::TransfersToNamada {
            nonce: 0.into(),
            transfers: vec![],
            valid_transfers_map: vec![],
        };
        let keys = vote_tallies::Keys::from(&event);
        let tally = Tally {
            voting_power: FractionalVotingPower::new(1, 3).unwrap(),
            seen_by: BTreeMap::from([(
                address::testing::established_address_1(),
                10.into(),
            )]),
            seen: false,
        };

        let result = write(&mut wl_storage, &keys, &event, &tally, false);

        assert!(result.is_ok());
        let body = wl_storage.read_bytes(&keys.body()).unwrap();
        assert_eq!(body, Some(event.try_to_vec().unwrap()));
        let seen = wl_storage.read_bytes(&keys.seen()).unwrap();
        assert_eq!(seen, Some(tally.seen.try_to_vec().unwrap()));
        let seen_by = wl_storage.read_bytes(&keys.seen_by()).unwrap();
        assert_eq!(seen_by, Some(tally.seen_by.try_to_vec().unwrap()));
        let voting_power = wl_storage.read_bytes(&keys.voting_power()).unwrap();
        assert_eq!(
            voting_power,
            Some(tally.voting_power.try_to_vec().unwrap())
        );
        let epoch =
            wl_storage.read_bytes(&keys.voting_started_epoch()).unwrap();
        assert_eq!(
            epoch,
            Some(
                wl_storage
                    .storage
                    .get_current_epoch()
                    .0
                    .try_to_vec()
                    .unwrap()
            )
        );
    }

    #[test]
    fn test_read_tally() {
        let mut wl_storage = TestWlStorage::default();
        let event = EthereumEvent::TransfersToNamada {
            nonce: 0.into(),
            transfers: vec![],
            valid_transfers_map: vec![],
        };
        let keys = vote_tallies::Keys::from(&event);
        let tally = Tally {
            voting_power: FractionalVotingPower::new(1, 3).unwrap(),
            seen_by: BTreeMap::from([(
                address::testing::established_address_1(),
                10.into(),
            )]),
            seen: false,
        };
        wl_storage
            .write_bytes(&keys.body(), &event.try_to_vec().unwrap())
            .unwrap();
        wl_storage
            .write_bytes(&keys.seen(), &tally.seen.try_to_vec().unwrap())
            .unwrap();
        wl_storage
            .write_bytes(&keys.seen_by(), &tally.seen_by.try_to_vec().unwrap())
            .unwrap();
        wl_storage
            .write_bytes(
                &keys.voting_power(),
                &tally.voting_power.try_to_vec().unwrap(),
            )
            .unwrap();
        wl_storage
            .write_bytes(
                &keys.voting_started_epoch(),
                &wl_storage
                    .storage
                    .get_block_height()
                    .0
                    .try_to_vec()
                    .unwrap(),
            )
            .unwrap();

        let result = read(&wl_storage, &keys);

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), tally);
    }
}
