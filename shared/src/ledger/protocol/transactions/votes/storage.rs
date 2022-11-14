use borsh::BorshSerialize;
use eyre::Result;

use super::Tally;
use crate::ledger::eth_bridge::storage::vote_tallies;
use crate::ledger::storage::{DBIter, Storage, StorageHasher, DB};

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

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::ledger::storage::testing::TestStorage;
    use crate::types::address;
    use crate::types::ethereum_events::EthereumEvent;
    use crate::types::voting_power::FractionalVotingPower;

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
}
