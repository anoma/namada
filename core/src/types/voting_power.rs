//! This module contains types related with validator voting power calculations.

use std::fmt::{Display, Formatter};
use std::iter::Sum;
use std::ops::{Add, AddAssign};

use borsh::{BorshDeserialize, BorshSchema, BorshSerialize};
use ethabi::ethereum_types as ethereum;
use eyre::{eyre, Result};
use num_rational::Ratio;
use serde::de::Visitor;
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};

/// Namada voting power, normalized to the range `0 - 2^32`.
#[derive(
    BorshSerialize,
    BorshDeserialize,
    BorshSchema,
    Default,
    Copy,
    Clone,
    PartialOrd,
    Ord,
    PartialEq,
    Eq,
    Hash,
    Debug,
)]
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

impl Display for FractionalVotingPower {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} / {}", self.0.numer(), self.0.denom())
    }
}

impl BorshSerialize for FractionalVotingPower {
    fn serialize<W: ark_serialize::Write>(
        &self,
        writer: &mut W,
    ) -> std::io::Result<()> {
        let (numer, denom): (u64, u64) = self.into();
        BorshSerialize::serialize(&(numer, denom), writer)
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

impl Serialize for FractionalVotingPower {
    fn serialize<S>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

struct VPVisitor;

impl<'de> Visitor<'de> for VPVisitor {
    type Value = FractionalVotingPower;

    fn expecting(&self, formatter: &mut Formatter) -> std::fmt::Result {
        formatter.write_str(
            "A '/' separated pair of numbers, the second of which is non-zero.",
        )
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        let [numer, denom]: [&str; 2] =
            value.split('/').collect::<Vec<&str>>().try_into().or(
                Err(de::Error::custom("Expected a '/' separated pair of numbers")),
            )?;
        let numer = numer.trim().parse::<u64>()
            .map_err(|e| de::Error::custom(e.to_string()))?;
        let denom = denom.trim().parse::<u64>()
            .map_err(|e| de::Error::custom(e.to_string()))?;
        FractionalVotingPower::new(numer, denom)
            .map_err(|e| de::Error::custom(e.to_string()))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        self.visit_str(&value)
    }
}

impl<'de> Deserialize<'de> for FractionalVotingPower {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer
            .deserialize_string(VPVisitor)
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

    /// Test that serde (de)-serializing pretty prints FractionalVotingPowers.
    #[test]
    fn test_serialize_fractional_voting_power() {
        let vp = FractionalVotingPower::new(1, 2).expect("Test failed");
        let serialized = serde_json::to_string(&vp).expect("Test failed");
        assert_eq!(serialized.as_str(), r#""1 / 2""#);
        let deserialized: FractionalVotingPower = serde_json::from_str(&serialized)
            .expect("Test failed");
        assert_eq!(deserialized, vp);
    }
}
