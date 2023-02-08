//! PoW challenge is used for testnet zero-fee transaction to prevent spam.

use std::fmt::Display;

use borsh::{BorshDeserialize, BorshSchema, BorshSerialize};
use namada_macros::StorageKeys;
use serde::{Deserialize, Serialize};

use super::storage_api::collections::{lazy_map, LazyCollection};
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
    address: &Address,
    difficulty: Difficulty,
    withdrawal_limit: token::Amount,
) -> storage_api::Result<()>
where
    S: StorageWrite,
{
    write_difficulty(storage, address, difficulty)?;
    write_withdrawal_limit(storage, address, withdrawal_limit)
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
    /// The address derived from the `WrapperTx`'s signer `pk` field
    pub source: Address,
    /// Parameters
    pub params: ChallengeParams,
}

/// PoW challenge parameters.
#[derive(
    Clone,
    Debug,
    BorshSerialize,
    BorshDeserialize,
    BorshSchema,
    PartialEq,
    Serialize,
    Deserialize,
)]
pub struct ChallengeParams {
    /// PoW difficulty
    pub difficulty: Difficulty,
    /// The counter value of the `transfer.target`.
    pub counter: Counter,
}

/// One must find a value for this type to solve a [`Challenge`] that is at
/// least of the matching difficulty of the challenge.
pub type SolutionValue = u64;
/// Size of `SolutionValue` when serialized with borsh
const SOLUTION_VAL_BYTES_LEN: usize = 8;

/// A [`SolutionValue`] with the [`Challenge`].
#[derive(
    Clone,
    Debug,
    BorshSerialize,
    BorshDeserialize,
    BorshSchema,
    Serialize,
    Deserialize,
)]
pub struct Solution {
    /// Challenge params
    pub params: ChallengeParams,
    /// Solution value, that produces hash with at least `difficulty` leading
    /// zeros
    pub value: SolutionValue,
}

impl ChallengeParams {
    /// Obtain a PoW challenge for a given transfer.
    pub fn new<S>(
        storage: &mut S,
        faucet_address: &Address,
        source: &Address,
    ) -> storage_api::Result<Self>
    where
        S: StorageRead + StorageWrite,
    {
        let difficulty = read_difficulty(storage, faucet_address)?;
        let counter = get_counter(storage, faucet_address, source)?;
        Ok(Self {
            difficulty,
            counter,
        })
    }
}

impl Challenge {
    /// Obtain a PoW challenge for a given transfer.
    pub fn new<S>(
        storage: &mut S,
        faucet_address: &Address,
        source: Address,
    ) -> storage_api::Result<Self>
    where
        S: StorageRead + StorageWrite,
    {
        let params = ChallengeParams::new(storage, faucet_address, &source)?;
        Ok(Self { source, params })
    }

    /// Try to find a solution to the [`Challenge`].
    pub fn solve(self) -> Solution {
        use std::io::Write;

        println!(
            "Looking for a solution with difficulty {}...",
            self.params.difficulty
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
            for i in 0..self.params.difficulty.0 as usize {
                if hash.0[i] != b'0' {
                    maybe_solution += 1;
                    continue 'outer;
                }
            }

            println!();
            println!("Found a solution: {}.", maybe_solution);
            stdout.flush().unwrap();
            return Solution {
                params: self.params,
                value: maybe_solution,
            };
        }
    }
}

impl Solution {
    /// Invalidate a solution if it's valid so that it cannot be used again by
    /// updating the counter in storage.
    pub fn invalidate_if_valid<S>(
        &self,
        storage: &mut S,
        faucet_address: &Address,
        source: &Address,
    ) -> storage_api::Result<bool>
    where
        S: StorageWrite + StorageRead,
    {
        if self.validate(storage, faucet_address, source.clone())? {
            self.apply_from_tx(storage, faucet_address, source)?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Apply a solution from a tx so that it cannot be used again.
    pub fn apply_from_tx<S>(
        &self,
        storage: &mut S,
        faucet_address: &Address,
        source: &Address,
    ) -> storage_api::Result<()>
    where
        S: StorageWrite + StorageRead,
    {
        increment_counter(storage, faucet_address, source, self.params.counter)
    }

    /// Verify a solution and that the counter has been increment to prevent
    /// solution replay.
    /// The difficulty of the challenge must match the one set in faucet's
    /// storage and the counter value.
    pub fn validate<S>(
        &self,
        storage: &S,
        faucet_address: &Address,
        source: Address,
    ) -> storage_api::Result<bool>
    where
        S: StorageRead,
    {
        let counter = get_counter(storage, faucet_address, &source)?;
        // Check that the counter matches expected counter
        if self.params.counter != counter {
            return Ok(false);
        }
        // Check that the difficulty matches expected difficulty
        let current_difficulty = read_difficulty(storage, faucet_address)?;
        if self.params.difficulty != current_difficulty {
            return Ok(false);
        }

        // Check the solution itself
        if !self.verify_solution(source) {
            return Ok(false);
        }

        Ok(true)
    }

    /// Verify that the given solution is correct. Note that this doesn't check
    /// the difficulty or the counter.
    pub fn verify_solution(&self, source: Address) -> bool {
        let challenge = Challenge {
            source,
            params: self.params.clone(),
        };
        let mut bytes = challenge.try_to_vec().expect("Serializable");
        let mut solution_bytes = self.value.try_to_vec().expect("Serializable");
        bytes.append(&mut solution_bytes);
        let hash = Hash::sha256(&bytes);

        // Check if it's a solution
        for i in 0..challenge.params.difficulty.0 as usize {
            if hash.0[i] != b'0' {
                return false;
            }
        }

        true
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
    pow_difficulty: &'static str,
    /// withdrawal limit
    withdrawal_limit: &'static str,
}

/// Storage key prefix to the `counters` field. The rest of the key is composed
/// from `LazyMap` stored at this key.
pub fn counter_prefix(address: &Address) -> storage::Key {
    storage::Key {
        segments: vec![
            DbKeySeg::AddressSeg(address.clone()),
            DbKeySeg::StringSeg(Keys::VALUES.counters.to_string()),
        ],
    }
}

/// Is the storage key for the `counters` field? If so, returns the owner.
pub fn is_counter_key<'a>(
    key: &'a storage::Key,
    faucet_address: &Address,
) -> Option<&'a Address> {
    match &key.segments[..] {
        [DbKeySeg::AddressSeg(address), DbKeySeg::StringSeg(sub_key), DbKeySeg::StringSeg(data), DbKeySeg::AddressSeg(owner)]
            if address == faucet_address
                && sub_key.as_str() == Keys::VALUES.counters
                && data.as_str() == lazy_map::DATA_SUBKEY =>
        {
            Some(owner)
        }
        _ => None,
    }
}

/// Storage key to the `difficulty` field.
pub fn difficulty_key(address: &Address) -> storage::Key {
    storage::Key {
        segments: vec![
            DbKeySeg::AddressSeg(address.clone()),
            DbKeySeg::StringSeg(Keys::VALUES.pow_difficulty.to_string()),
        ],
    }
}

/// Is the storage key for the `difficulty` field?
pub fn is_difficulty_key(key: &storage::Key, faucet_address: &Address) -> bool {
    matches!(
        &key.segments[..],
        [
            DbKeySeg::AddressSeg(address),
            DbKeySeg::StringSeg(sub_key),
        ] if address == faucet_address && sub_key.as_str() == Keys::VALUES.pow_difficulty,
    )
}

/// Storage key to the `withdrawal_limit` field.
pub fn withdrawal_limit_key(address: &Address) -> storage::Key {
    storage::Key {
        segments: vec![
            DbKeySeg::AddressSeg(address.clone()),
            DbKeySeg::StringSeg(Keys::VALUES.withdrawal_limit.to_string()),
        ],
    }
}

/// Is the storage key for the `withdrawal_limit` field?
pub fn is_withdrawal_limit_key(
    key: &storage::Key,
    faucet_address: &Address,
) -> bool {
    matches!(
        &key.segments[..],
        [
            DbKeySeg::AddressSeg(address),
            DbKeySeg::StringSeg(sub_key),
        ] if address == faucet_address && sub_key.as_str() == Keys::VALUES.withdrawal_limit,
    )
}

/// Read faucet's counter value for a given target address.
pub fn get_counter<S>(
    storage: &S,
    faucet_address: &Address,
    source: &Address,
) -> storage_api::Result<Counter>
where
    S: StorageRead,
{
    let counter: Counter = counters_handle(faucet_address)
        .get(storage, source)?
        // `0` if not previously set
        .unwrap_or_default();
    Ok(counter)
}

/// Increment faucet's counter value for a given source address.
pub fn increment_counter<S>(
    storage: &mut S,
    faucet_address: &Address,
    source: &Address,
    current_counter: Counter,
) -> storage_api::Result<()>
where
    S: StorageWrite + StorageRead,
{
    counters_handle(faucet_address).insert(
        storage,
        source.clone(),
        current_counter + 1,
    )?;
    Ok(())
}

/// A handle to read/write withdrawal counters
pub fn counters_handle(address: &Address) -> LazyMap<Address, Counter> {
    LazyMap::open(counter_prefix(address))
}

/// PoW difficulty (value between `0..=9`).
#[derive(
    Copy,
    Clone,
    Debug,
    Default,
    BorshSerialize,
    BorshDeserialize,
    BorshSchema,
    Eq,
    PartialEq,
    PartialOrd,
    Ord,
    Serialize,
    Deserialize,
)]
#[serde(transparent)]
pub struct Difficulty(u8);
impl Difficulty {
    /// The value must be between `0..=9` (inclusive upper bound).
    pub fn try_new(raw: u8) -> Option<Difficulty> {
        if raw > 9 {
            None
        } else {
            Some(Self(raw))
        }
    }
}

impl Display for Difficulty {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

/// Read PoW [`Difficulty`].
pub fn read_difficulty<S>(
    storage: &S,
    address: &Address,
) -> storage_api::Result<Difficulty>
where
    S: StorageRead,
{
    let difficulty = storage
        .read(&difficulty_key(address))?
        .expect("difficulty must always be set");
    Ok(difficulty)
}

/// Write PoW [`Difficulty`].
pub fn write_difficulty<S>(
    storage: &mut S,
    address: &Address,
    difficulty: Difficulty,
) -> storage_api::Result<()>
where
    S: StorageWrite,
{
    storage.write(&difficulty_key(address), difficulty)
}

/// Read the withdrawal limit.
pub fn read_withdrawal_limit<S>(
    storage: &S,
    address: &Address,
) -> storage_api::Result<token::Amount>
where
    S: StorageRead,
{
    let withdrawal_limit = storage
        .read(&withdrawal_limit_key(address))?
        .expect("withdrawal_limit must always be set");
    Ok(withdrawal_limit)
}

/// Write faucet withdrawal limit
pub fn write_withdrawal_limit<S>(
    storage: &mut S,
    address: &Address,
    withdrawal_limit: token::Amount,
) -> Result<(), storage_api::Error>
where
    S: StorageWrite,
{
    storage.write(&withdrawal_limit_key(address), withdrawal_limit)
}

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn test_solution_val_bytes_len() {
        let val: SolutionValue = 10;
        let bytes = val.try_to_vec().unwrap();
        assert_eq!(bytes.len(), SOLUTION_VAL_BYTES_LEN);
    }
}

#[cfg(test)]
mod test_with_tx_and_vp_env {
    // IMPORTANT: do not import anything directly from this `crate` here, only
    // via `namada_tests`. This gets us around the `core -> tests -> core` dep
    // cycle, which is okay, because `tests` is only a `dev-dependency` of
    // core and allows us to test the code in the same module as its defined.
    //
    // This imports the same code as `super::*` but from a different version of
    // this crate (one that `namada_tests` depends on). It's re-exported
    // from `namada_tests` so that we can use it together with
    // `namada_tests` modules back in here.
    use namada_tests::namada::core::ledger::storage_api;
    use namada_tests::namada::core::ledger::testnet_pow::*;
    use namada_tests::namada::core::types::{address, token};
    use namada_tests::tx::{self, TestTxEnv};
    use namada_tests::vp;

    #[test]
    fn test_challenge_and_solution() -> storage_api::Result<()> {
        let faucet_address = address::testing::established_address_1();
        let difficulty = Difficulty::try_new(1).unwrap();
        let withdrawal_limit = token::Amount::whole(1_000);

        let mut tx_env = TestTxEnv::default();

        // Source address that's using PoW (this would be derived from the tx
        // wrapper pk)
        let source = address::testing::established_address_2();

        // Ensure that the addresses exists, so we can use them in a tx
        tx_env.spawn_accounts([&faucet_address, &source]);

        init_faucet_storage(
            &mut tx_env.wl_storage,
            &faucet_address,
            difficulty,
            withdrawal_limit,
        )?;
        tx_env.commit_genesis();

        let challenge = Challenge::new(
            &mut tx_env.wl_storage,
            &faucet_address,
            source.clone(),
        )?;

        let solution = challenge.solve();

        // The solution must be valid
        assert!(solution.verify_solution(source.clone()));

        // Changing the solution to `0` invalidates it
        {
            let mut solution = solution.clone();
            solution.value = 0;
            // If you're unlucky and this fails, try changing the solution to
            // a different literal.
            assert!(!solution.verify_solution(source.clone()));
        }
        // Changing the counter invalidates it
        {
            let mut solution = solution.clone();
            solution.params.counter = 10;
            // If you're unlucky and this fails, try changing the counter to
            // a different literal.
            assert!(!solution.verify_solution(source.clone()));
        }

        // Apply the solution from a tx
        vp::vp_host_env::init_from_tx(
            faucet_address.clone(),
            tx_env,
            |_addr| {
                solution
                    .apply_from_tx(tx::ctx(), &faucet_address, &source)
                    .unwrap();
            },
        );

        // Check that it's valid
        let is_valid = solution.validate(
            &vp::ctx().pre(),
            &faucet_address,
            source.clone(),
        )?;
        assert!(is_valid);

        // Commit the tx
        let vp_env = vp::vp_host_env::take();
        tx::tx_host_env::set_from_vp_env(vp_env);
        tx::tx_host_env::commit_tx_and_block();
        let tx_env = tx::tx_host_env::take();

        // Re-apply the same solution from a tx
        vp::vp_host_env::init_from_tx(
            faucet_address.clone(),
            tx_env,
            |_addr| {
                solution
                    .apply_from_tx(tx::ctx(), &faucet_address, &source)
                    .unwrap();
            },
        );

        // Check that it's not longer valid
        let is_valid =
            solution.validate(&vp::ctx().pre(), &faucet_address, source)?;
        assert!(!is_valid);

        Ok(())
    }
}
