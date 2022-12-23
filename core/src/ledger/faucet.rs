//! Faucet PoW challenge for the VP and client support.

use borsh::{BorshDeserialize, BorshSerialize};
use namada_macros::StorageKeys;
use serde::{Deserialize, Serialize};

use super::storage_api::collections::LazyCollection;
use super::storage_api::{self, StorageRead, StorageWrite};
use crate::ledger::storage_api::collections::LazyMap;
use crate::types::address::Address;
use crate::types::hash::Hash;
use crate::types::storage::{self, DbKeySeg};
use crate::types::token;

/// Initialize faucet's storage. This must be called at genesis if faucet
/// account is being used.
pub fn init_faucet_storage<S>(
    storage: &mut S,
    difficulty: Difficulty,
) -> storage_api::Result<()>
where
    S: StorageWrite,
{
    write_difficulty(storage, difficulty)
}

/// Counters are associated with transfer target addresses.
pub type Counter = u64;

/// A PoW challenge that must be provably solved to withdraw from faucet.
#[derive(
    Clone,
    Debug,
    BorshSerialize,
    BorshDeserialize,
    PartialEq,
    Serialize,
    Deserialize,
)]
pub struct Challenge {
    /// Transfer tx data
    pub transfer: token::Transfer,
    /// PoW difficulty
    pub difficulty: u8,
    /// The counter value of the `transfer.target`
    pub counter: Counter,
}

/// One must find a value for this type to solve a [`Challenge`] that is at
/// least of the matching difficulty of the challenge.
pub type SolutionValue = u64;
/// Size of `SolutionValue` when serialized with borsh
const SOLUTION_VAL_BYTES_LEN: usize = 8;

/// A [`SolutionValue`] with the [`Challenge`].
pub struct Solution {
    /// Challenge
    pub challenge: Challenge,
    /// Solution
    pub solution: SolutionValue,
}

impl Challenge {
    /// Obtain a PoW challenge for a given transfer.
    pub fn new<S>(
        storage: &mut S,
        transfer: token::Transfer,
    ) -> storage_api::Result<Self>
    where
        S: StorageWrite + for<'iter> StorageRead<'iter>,
    {
        let difficulty = read_difficulty(storage)?;
        let counter: Counter = counters_handle()
            .get(storage, &transfer.target)?
            // `0` if not previously set
            .unwrap_or_default();
        Ok(Self {
            transfer,
            difficulty,
            counter,
        })
    }

    /// Try to find a solution to the [`Challenge`].
    pub fn solve(self) -> Solution {
        use std::io::Write;

        println!(
            "Looking for a solution with difficulty {}...",
            self.difficulty
        );
        let challenge_bytes = self.try_to_vec().expect("Serializable");
        let challenge_len = challenge_bytes.len();
        let mut stdout = std::io::stdout();

        // Pre-allocate for the bytes
        let mut bytes: Vec<u8> =
            vec![0; challenge_bytes.len() + SOLUTION_VAL_BYTES_LEN];

        // Set the first part from `challenge_bytes`...
        for (old, new) in
            bytes[0..challenge_len].iter_mut().zip(&challenge_bytes[..])
        {
            *old = *new;
        }
        let mut maybe_solution: SolutionValue = 0;
        'outer: loop {
            stdout.flush().unwrap();
            print!("\rChecking {}.", maybe_solution);
            let solution_bytes =
                maybe_solution.try_to_vec().expect("Serializable");
            // ...and the second part from `solution_bytes`
            for (old, new) in
                bytes[challenge_len..].iter_mut().zip(&solution_bytes[..])
            {
                *old = *new;
            }
            let hash = Hash::sha256(&bytes);

            // Check if it's a solution
            for i in 0..self.difficulty as usize {
                if hash.0[i] != b'0' {
                    maybe_solution += 1;
                    continue 'outer;
                }
            }

            println!();
            println!("Found solution. {}", maybe_solution);
            stdout.flush().unwrap();
            return Solution {
                challenge: self,
                solution: maybe_solution,
            };
        }
    }
}

impl Solution {
    /// Verify a solution
    pub fn verify<S>(&self, storage: &mut S) -> storage_api::Result<bool>
    where
        S: for<'iter> StorageRead<'iter>,
    {
        let current_difficulty = read_difficulty(storage)?;
        if self.challenge.difficulty != current_difficulty {
            return Err(storage_api::Error::new_const("Invalid difficulty"));
        }

        let current_counter: Counter = counters_handle()
            .get(storage, &self.challenge.transfer.target)?
            // Same as in `Challenge::new` - use `0` if not previously set
            .unwrap_or_default();
        if self.challenge.counter != current_counter {
            return Err(storage_api::Error::new_const("Invalid counter"));
        }

        let mut bytes = self.challenge.try_to_vec().expect("Serializable");
        let mut solution_bytes =
            self.solution.try_to_vec().expect("Serializable");
        bytes.append(&mut solution_bytes);
        let hash = Hash::sha256(&bytes);

        // Check if it's a solution
        for i in 0..current_difficulty as usize {
            if hash.0[i] != b'0' {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

/// Storage keys
#[derive(StorageKeys)]
pub struct Keys {
    /// Withdrawal counters associated with recipient addresses. To withdraw
    /// tokens from faucet, one must find a solution to a PoW challenge
    /// containing the current value of their counter (or `0` is none).
    counters: &'static str,
    /// PoW difficulty
    difficulty: &'static str,
}

/// Storage key to the `counters` field.
pub fn counter_key() -> storage::Key {
    storage::Key {
        segments: vec![DbKeySeg::StringSeg(Keys::VALUES.counters.to_string())],
    }
}

/// Storage key to the `difficulty` field.
pub fn difficulty_key() -> storage::Key {
    storage::Key {
        segments: vec![DbKeySeg::StringSeg(
            Keys::VALUES.difficulty.to_string(),
        )],
    }
}

/// A handle to read/write withdrawal counters
pub fn counters_handle() -> LazyMap<Address, Counter> {
    LazyMap::open(counter_key())
}

/// PoW difficulty (value between `0..=9`).
#[derive(Copy, Clone, Debug, BorshSerialize, BorshDeserialize)]
pub struct Difficulty(u8);
impl Difficulty {
    /// The value must be between `0..=9` (inclusive upper bound).
    pub fn try_new(raw: u8) -> Option<Difficulty> {
        if raw > 9 { None } else { Some(Self(raw)) }
    }
}

/// Read PoW [`Difficulty`].
pub fn read_difficulty<S>(storage: &S) -> storage_api::Result<u8>
where
    S: for<'iter> StorageRead<'iter>,
{
    let Difficulty(raw) = storage
        .read(&difficulty_key())?
        .expect("difficulty must always be set");
    Ok(raw)
}

/// Write PoW [`Difficulty`].
pub fn write_difficulty<S>(
    storage: &mut S,
    difficulty: Difficulty,
) -> storage_api::Result<()>
where
    S: StorageWrite,
{
    storage.write(&difficulty_key(), difficulty)
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::ledger::storage::testing::TestStorage;
    use crate::types::address;

    #[test]
    fn test_solution_val_bytes_len() {
        let val: SolutionValue = 10;
        let bytes = val.try_to_vec().unwrap();
        assert_eq!(bytes.len(), SOLUTION_VAL_BYTES_LEN);
    }

    #[test]
    fn test_challenge_and_solution() -> storage_api::Result<()> {
        let difficulty = Difficulty::try_new(2).unwrap();
        let mut storage = TestStorage::default();

        init_faucet_storage(&mut storage, difficulty)?;

        let transfer = token::Transfer {
            source: address::testing::established_address_1(),
            target: address::testing::established_address_2(),
            token: address::testing::established_address_3(),
            sub_prefix: None,
            amount: token::Amount::whole(1_000),
            key: None,
            shielded: None,
        };

        let challenge = Challenge::new(&mut storage, transfer.clone()).unwrap();

        let mut solution = challenge.solve();

        assert!(solution.verify(&mut storage)?);

        solution.solution = 0;
        assert!(!solution.verify(&mut storage)?);

        Ok(())
    }
}
