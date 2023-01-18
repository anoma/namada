//! This module contains types related with validator voting power calculations.

use std::iter::Sum;
use std::ops::{Add, AddAssign};

use borsh::{BorshDeserialize, BorshSchema, BorshSerialize};
use ethabi::ethereum_types as ethereum;
use eyre::{eyre, Result};
use num_rational::Ratio;

/// Namada voting power, normalized to the range `0 - 2^32`.
pub struct EthBridgeVotingPower(u64);

impl From<&FractionalVotingPower> for EthBridgeVotingPower {
    fn from(ratio: &FractionalVotingPower) -> Self {
        // normalize the voting power
        // https://github.com/anoma/ethereum-bridge/blob/fe93d2e95ddb193a759811a79c8464ad4d709c12/test/utils/utilities.js#L29
        const NORMALIZED_VOTING_POWER: u64 = 1 << 32;

        let voting_power = ratio.0 * NORMALIZED_VOTING_POWER;
        let voting_power = voting_power.round().to_integer();

        Self(voting_power)
    }
}

impl From<FractionalVotingPower> for EthBridgeVotingPower {
    #[inline]
    fn from(ratio: FractionalVotingPower) -> Self {
        (&ratio).into()
    }
}

impl From<EthBridgeVotingPower> for ethereum::U256 {
    #[inline]
    fn from(EthBridgeVotingPower(voting_power): EthBridgeVotingPower) -> Self {
        voting_power.into()
    }
}

impl From<EthBridgeVotingPower> for u64 {
    #[inline]
    fn from(EthBridgeVotingPower(voting_power): EthBridgeVotingPower) -> u64 {
        voting_power
    }
}

/// A fraction of the total voting power. This should always be a reduced
/// fraction that is between zero and one inclusive.
#[derive(Clone, PartialOrd, Ord, PartialEq, Eq, Hash, Debug)]
pub struct FractionalVotingPower(Ratio<u64>);

impl FractionalVotingPower {
    /// Two thirds of the voting power.
    pub const TWO_THIRDS: FractionalVotingPower =
        FractionalVotingPower(Ratio::new_raw(2, 3));

    /// Create a new FractionalVotingPower. It must be between zero and one
    /// inclusive.
    pub fn new(numer: u64, denom: u64) -> Result<Self> {
        if denom == 0 {
            return Err(eyre!("denominator can't be zero"));
        }
        let ratio: Ratio<u64> = (numer, denom).into();
        if ratio > 1.into() {
            return Err(eyre!(
                "fractional voting power cannot be greater than one"
            ));
        }
        Ok(Self(ratio))
    }
}

impl Default for FractionalVotingPower {
    fn default() -> Self {
        Self::new(0, 1).unwrap()
    }
}

impl From<&FractionalVotingPower> for (u64, u64) {
    fn from(ratio: &FractionalVotingPower) -> Self {
        (ratio.0.numer().to_owned(), ratio.0.denom().to_owned())
    }
}

impl Sum for FractionalVotingPower {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(Self::default(), Add::add)
    }
}

impl Add<FractionalVotingPower> for FractionalVotingPower {
    type Output = Self;

    fn add(self, rhs: FractionalVotingPower) -> Self::Output {
        Self(self.0 + rhs.0)
    }
}

impl Add<&FractionalVotingPower> for FractionalVotingPower {
    type Output = Self;

    fn add(self, rhs: &FractionalVotingPower) -> Self::Output {
        Self(self.0 + rhs.0)
    }
}

impl AddAssign<FractionalVotingPower> for FractionalVotingPower {
    fn add_assign(&mut self, rhs: FractionalVotingPower) {
        *self = Self(self.0 + rhs.0)
    }
}

impl AddAssign<&FractionalVotingPower> for FractionalVotingPower {
    fn add_assign(&mut self, rhs: &FractionalVotingPower) {
        *self = Self(self.0 + rhs.0)
    }
}

impl BorshSerialize for FractionalVotingPower {
    fn serialize<W: ark_serialize::Write>(
        &self,
        writer: &mut W,
    ) -> std::io::Result<()> {
        let (numer, denom): (u64, u64) = self.into();
        (numer, denom).serialize(writer)
    }
}

impl BorshDeserialize for FractionalVotingPower {
    fn deserialize(buf: &mut &[u8]) -> std::io::Result<Self> {
        let (numer, denom): (u64, u64) = BorshDeserialize::deserialize(buf)?;
        Ok(FractionalVotingPower(Ratio::<u64>::new(numer, denom)))
    }
}

impl BorshSchema for FractionalVotingPower {
    fn add_definitions_recursively(
        definitions: &mut std::collections::HashMap<
            borsh::schema::Declaration,
            borsh::schema::Definition,
        >,
    ) {
        let fields =
            borsh::schema::Fields::UnnamedFields(borsh::maybestd::vec![
                u64::declaration(),
                u64::declaration()
            ]);
        let definition = borsh::schema::Definition::Struct { fields };
        Self::add_definition(Self::declaration(), definition, definitions);
    }

    fn declaration() -> borsh::schema::Declaration {
        "FractionalVotingPower".into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// This test is ultimately just exercising the underlying
    /// library we use for fractions, we want to make sure
    /// operators work as expected with our FractionalVotingPower
    /// type itself
    #[test]
    fn test_fractional_voting_power_ord_eq() {
        assert!(
            FractionalVotingPower::TWO_THIRDS
                > FractionalVotingPower::new(1, 4).unwrap()
        );
        assert!(
            FractionalVotingPower::new(1, 3).unwrap()
                > FractionalVotingPower::new(1, 4).unwrap()
        );
        assert!(
            FractionalVotingPower::new(1, 3).unwrap()
                == FractionalVotingPower::new(2, 6).unwrap()
        );
    }

    /// Test error handling on the FractionalVotingPower type
    #[test]
    fn test_fractional_voting_power_valid_fractions() {
        assert!(FractionalVotingPower::new(0, 0).is_err());
        assert!(FractionalVotingPower::new(1, 0).is_err());
        assert!(FractionalVotingPower::new(0, 1).is_ok());
        assert!(FractionalVotingPower::new(1, 1).is_ok());
        assert!(FractionalVotingPower::new(1, 2).is_ok());
        assert!(FractionalVotingPower::new(3, 2).is_err());
    }
}
