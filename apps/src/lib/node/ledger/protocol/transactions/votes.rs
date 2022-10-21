//! Logic and data types relating to tallying validators' votes for pieces of
//! data stored in the ledger, where those pieces of data should only be acted
//! on once they have received enough votes
use std::collections::{BTreeSet, HashMap};

use borsh::{BorshDeserialize, BorshSchema, BorshSerialize};
use eyre::{eyre, Result};
use namada::ledger::eth_bridge::storage::vote_tallies;
use namada::ledger::storage::traits::StorageHasher;
use namada::ledger::storage::{DBIter, Storage, DB};
use namada::types::address::Address;
use namada::types::storage::BlockHeight;
use namada::types::voting_power::FractionalVotingPower;

use crate::node::ledger::protocol::transactions::read;

#[derive(
    Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, BorshSchema,
)]
/// Represents all the information needed to tally a piece of data that may be
/// voted for over multiple epochs
pub struct Tally {
    /// The total voting power that's voted for this event across all epochs
    pub voting_power: FractionalVotingPower,
    /// The addresses of validators that voted for this event. We use a
    /// set type as validators should only be able to vote at most once,
    /// and [`BTreeSet`] specifically as we want this field to be
    /// deterministically ordered for storage.
    pub seen_by: BTreeSet<Address>,
    /// Whether this event has been acted on or not - this should only ever
    /// transition from `false` to `true`, once there is enough voting power
    pub seen: bool,
}

/// Calculate a new [`Tally`] based on some validators' fractional voting powers
/// as specific block heights
pub fn calculate_new(
    seen_by: &BTreeSet<(Address, BlockHeight)>,
    voting_powers: &HashMap<(Address, BlockHeight), FractionalVotingPower>,
) -> Result<Tally> {
    let mut seen_by_voting_power = FractionalVotingPower::default();
    for (validator, block_height) in seen_by {
        match voting_powers
            .get(&(validator.to_owned(), block_height.to_owned()))
        {
            Some(voting_power) => seen_by_voting_power += voting_power,
            None => {
                return Err(eyre!(
                    "voting power was not provided for validator {}",
                    validator
                ));
            }
        };
    }

    let newly_confirmed =
        seen_by_voting_power > FractionalVotingPower::TWO_THIRDS;
    Ok(Tally {
        voting_power: seen_by_voting_power,
        seen_by: seen_by
            .iter()
            .map(|(validator, _)| validator.to_owned())
            .collect(),
        seen: newly_confirmed,
    })
}

/// Calculate an updated [`Tally`] based on one that is in storage under `keys`,
/// and some new votes
pub fn calculate_updated<D, H, T>(
    store: &mut Storage<D, H>,
    keys: &vote_tallies::Keys<T>,
    _voting_powers: &HashMap<(Address, BlockHeight), FractionalVotingPower>,
) -> Result<Tally>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
    T: BorshDeserialize,
{
    // TODO(namada#515): implement this
    let _body: T = read::value(store, &keys.body())?;
    let seen: bool = read::value(store, &keys.seen())?;
    let seen_by: BTreeSet<Address> = read::value(store, &keys.seen_by())?;
    let voting_power: FractionalVotingPower =
        read::value(store, &keys.voting_power())?;

    let tally = Tally {
        voting_power,
        seen_by,
        seen,
    };

    tracing::warn!(
        ?tally,
        "Updating events is not implemented yet, so the returned vote tally \
         will be identical to the one in storage",
    );
    Ok(tally)
}

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
