use borsh::{BorshDeserialize, BorshSerialize};
use eyre::Result;
use namada_core::ledger::storage::{DBIter, Storage, StorageHasher, DB};
use namada_core::types::voting_power::FractionalVotingPower;

use super::{Tally, Votes};
use crate::storage::vote_tallies;

pub fn write<D, H, T>(
    storage: &mut Storage<D, H>,
    keys: &vote_tallies::Keys<T>,
    body: &T,
    tally: &Tally,
) -> Result<()>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
    T: BorshSerialize,
{
    storage.write(&keys.body(), &body.try_to_vec()?)?;
    storage.write(&keys.seen(), &tally.seen.try_to_vec()?)?;
    storage.write(&keys.seen_by(), &tally.seen_by.try_to_vec()?)?;
    storage.write(&keys.voting_power(), &tally.voting_power.try_to_vec()?)?;
    Ok(())
}

#[allow(dead_code)]
pub fn read<D, H, T>(
    storage: &mut Storage<D, H>,
    keys: &vote_tallies::Keys<T>,
) -> Result<Tally>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    let seen: bool = super::read::value(storage, &keys.seen())?;
    let seen_by: Votes = super::read::value(storage, &keys.seen_by())?;
    let voting_power: FractionalVotingPower =
        super::read::value(storage, &keys.voting_power())?;

    Ok(Tally {
        voting_power,
        seen_by,
        seen,
    })
}

#[inline]
pub fn read_body<D, H, T>(
    storage: &Storage<D, H>,
    keys: &vote_tallies::Keys<T>,
) -> Result<T>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
    T: BorshDeserialize,
{
    super::read::value(storage, &keys.body())
}

#[inline]
pub fn maybe_read_seen<D, H, T>(
    storage: &Storage<D, H>,
    keys: &vote_tallies::Keys<T>,
) -> Result<Option<bool>>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
    T: BorshDeserialize,
{
    super::read::maybe_value(storage, &keys.seen())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use namada_core::ledger::storage::testing::TestStorage;
    use namada_core::types::address;
    use namada_core::types::ethereum_events::EthereumEvent;
    use namada_core::types::voting_power::FractionalVotingPower;

    use super::*;

    #[test]
    fn test_write_tally() {
        let mut storage = TestStorage::default();
        let event = EthereumEvent::TransfersToNamada {
            nonce: 0.into(),
            transfers: vec![],
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

        let result = write(&mut storage, &keys, &event, &tally);

        assert!(result.is_ok());
        let (body, _) = storage.read(&keys.body()).unwrap();
        assert_eq!(body, Some(event.try_to_vec().unwrap()));
        let (seen, _) = storage.read(&keys.seen()).unwrap();
        assert_eq!(seen, Some(tally.seen.try_to_vec().unwrap()));
        let (seen_by, _) = storage.read(&keys.seen_by()).unwrap();
        assert_eq!(seen_by, Some(tally.seen_by.try_to_vec().unwrap()));
        let (voting_power, _) = storage.read(&keys.voting_power()).unwrap();
        assert_eq!(
            voting_power,
            Some(tally.voting_power.try_to_vec().unwrap())
        );
    }

    #[test]
    fn test_read_tally() {
        let mut storage = TestStorage::default();
        let event = EthereumEvent::TransfersToNamada {
            nonce: 0.into(),
            transfers: vec![],
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
        storage
            .write(&keys.body(), &event.try_to_vec().unwrap())
            .unwrap();
        storage
            .write(&keys.seen(), &tally.seen.try_to_vec().unwrap())
            .unwrap();
        storage
            .write(&keys.seen_by(), &tally.seen_by.try_to_vec().unwrap())
            .unwrap();
        storage
            .write(
                &keys.voting_power(),
                &tally.voting_power.try_to_vec().unwrap(),
            )
            .unwrap();

        let result = read(&mut storage, &keys);

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), tally);
    }
}
