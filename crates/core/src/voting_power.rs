//! This module contains types related with validator voting power calculations.

use std::collections::BTreeMap;
use std::fmt::{Display, Formatter};
use std::io::Read;
use std::iter::Sum;
use std::ops::{Add, AddAssign, Mul};

use borsh::{BorshDeserialize, BorshSchema, BorshSerialize};
use ethabi::ethereum_types as ethereum;
use eyre::{eyre, Result};
use num_rational::Ratio;
use num_traits::ops::checked::CheckedAdd;
use serde::de::Visitor;
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};

use crate::token::Amount;
use crate::uint::Uint;

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
pub struct EthBridgeVotingPower(u128);

impl EthBridgeVotingPower {
    /// Maximum value that can be represented for the voting power
    /// stored in an Ethereum bridge smart contract.
    ///
    /// The smart contract uses 12-byte integers.
    pub const MAX: Self = Self((1 << 96) - 1);
}

impl From<u64> for EthBridgeVotingPower {
    #[inline]
    fn from(val: u64) -> Self {
        Self(val as u128)
    }
}

impl TryFrom<u128> for EthBridgeVotingPower {
    type Error = ();

    #[inline]
    fn try_from(val: u128) -> Result<Self, ()> {
        if val <= Self::MAX.0 {
            Ok(Self(val))
        } else {
            Err(())
        }
    }
}

impl From<&FractionalVotingPower> for EthBridgeVotingPower {
    fn from(FractionalVotingPower(ratio): &FractionalVotingPower) -> Self {
        let max_bridge_voting_power = Uint::from(EthBridgeVotingPower::MAX.0);

        let voting_power = ratio * max_bridge_voting_power;
        let voting_power = voting_power.round().to_integer().low_u128();

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

impl From<EthBridgeVotingPower> for u128 {
    #[inline]
    fn from(EthBridgeVotingPower(voting_power): EthBridgeVotingPower) -> u128 {
        voting_power
    }
}

/// A fraction of the total voting power. This should always be a reduced
/// fraction that is between zero and one inclusive.
#[derive(Copy, Clone, PartialOrd, Ord, PartialEq, Eq, Hash, Debug)]
pub struct FractionalVotingPower(Ratio<Uint>);

impl FractionalVotingPower {
    /// Half of the voting power.
    pub const HALF: FractionalVotingPower = FractionalVotingPower(
        Ratio::new_raw(Uint::from_u64(1), Uint::from_u64(2)),
    );
    /// Null voting power.
    pub const NULL: FractionalVotingPower = FractionalVotingPower(
        Ratio::new_raw(Uint::from_u64(0), Uint::from_u64(1)),
    );
    /// One third of the voting power.
    pub const ONE_THIRD: FractionalVotingPower = FractionalVotingPower(
        Ratio::new_raw(Uint::from_u64(1), Uint::from_u64(3)),
    );
    /// Two thirds of the voting power.
    pub const TWO_THIRDS: FractionalVotingPower = FractionalVotingPower(
        Ratio::new_raw(Uint::from_u64(2), Uint::from_u64(3)),
    );
    /// 100% of the voting power.
    pub const WHOLE: FractionalVotingPower = FractionalVotingPower(
        Ratio::new_raw(Uint::from_u64(1), Uint::from_u64(1)),
    );

    /// Create a new [`FractionalVotingPower`]. It must be between zero and one
    /// inclusive.
    pub fn new(numer: Uint, denom: Uint) -> Result<Self> {
        if denom.is_zero() {
            return Err(eyre!("denominator can't be zero"));
        }
        let ratio: Ratio<Uint> = (numer, denom).into();
        if ratio > Self::WHOLE.0 {
            return Err(eyre!(
                "fractional voting power cannot be greater than one"
            ));
        }
        Ok(Self(ratio))
    }

    /// Create a new [`FractionalVotingPower`], from a [`u64`]
    /// numerator and denominator.
    #[inline]
    pub fn new_u64(numer: u64, denom: u64) -> Result<Self> {
        Self::new(Uint::from_u64(numer), Uint::from_u64(denom))
    }
}

impl Default for FractionalVotingPower {
    #[inline(always)]
    fn default() -> Self {
        Self::NULL
    }
}

impl From<&FractionalVotingPower> for (Uint, Uint) {
    fn from(ratio: &FractionalVotingPower) -> Self {
        (ratio.0.numer().to_owned(), ratio.0.denom().to_owned())
    }
}

impl Sum for FractionalVotingPower {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(Self::default(), Add::add)
    }
}

impl Mul<FractionalVotingPower> for FractionalVotingPower {
    type Output = Self;

    fn mul(self, rhs: FractionalVotingPower) -> Self::Output {
        self * &rhs
    }
}

impl Mul<&FractionalVotingPower> for FractionalVotingPower {
    type Output = Self;

    fn mul(self, rhs: &FractionalVotingPower) -> Self::Output {
        Self(self.0 * rhs.0)
    }
}

impl Mul<Amount> for FractionalVotingPower {
    type Output = Amount;

    fn mul(self, rhs: Amount) -> Self::Output {
        self * &rhs
    }
}

impl Mul<&Amount> for FractionalVotingPower {
    type Output = Amount;

    fn mul(self, &rhs: &Amount) -> Self::Output {
        let whole: Uint = rhs.into();
        let fraction = (self.0 * whole).to_integer();
        Amount::from_uint(fraction, 0u8).unwrap()
    }
}

impl Add<FractionalVotingPower> for FractionalVotingPower {
    type Output = Self;

    fn add(self, rhs: FractionalVotingPower) -> Self::Output {
        self + &rhs
    }
}

impl Add<&FractionalVotingPower> for FractionalVotingPower {
    type Output = Self;

    fn add(self, rhs: &FractionalVotingPower) -> Self::Output {
        self.0
            .checked_add(&rhs.0)
            .map(Self)
            // cap fractional voting power to 1/1
            .and_then(|power| {
                (power <= FractionalVotingPower::WHOLE).then_some(power)
            })
            .unwrap_or(FractionalVotingPower::WHOLE)
    }
}

impl AddAssign<FractionalVotingPower> for FractionalVotingPower {
    fn add_assign(&mut self, rhs: FractionalVotingPower) {
        *self = *self + rhs
    }
}

impl AddAssign<&FractionalVotingPower> for FractionalVotingPower {
    fn add_assign(&mut self, rhs: &FractionalVotingPower) {
        *self = *self + rhs
    }
}

impl Display for FractionalVotingPower {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} / {}", self.0.numer(), self.0.denom())
    }
}

impl BorshSerialize for FractionalVotingPower {
    fn serialize<W: std::io::Write>(
        &self,
        writer: &mut W,
    ) -> std::io::Result<()> {
        let (numer, denom): (Uint, Uint) = self.into();
        BorshSerialize::serialize(&(numer, denom), writer)
    }
}

impl BorshDeserialize for FractionalVotingPower {
    fn deserialize_reader<R: Read>(reader: &mut R) -> std::io::Result<Self> {
        let (numer, denom): (Uint, Uint) =
            BorshDeserialize::deserialize_reader(reader)?;
        Ok(FractionalVotingPower(Ratio::<Uint>::new(numer, denom)))
    }
}

impl BorshSchema for FractionalVotingPower {
    fn add_definitions_recursively(
        definitions: &mut BTreeMap<
            borsh::schema::Declaration,
            borsh::schema::Definition,
        >,
    ) {
        let fields = borsh::schema::Fields::UnnamedFields(vec![
            Uint::declaration(),
            Uint::declaration(),
        ]);
        let definition = borsh::schema::Definition::Struct { fields };
        borsh::schema::add_definition(
            Self::declaration(),
            definition,
            definitions,
        );
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
            value.split('/').collect::<Vec<&str>>().try_into().or(Err(
                de::Error::custom("Expected a '/' separated pair of numbers"),
            ))?;
        let numer = Uint::from_str_radix(numer.trim(), 10)
            .map_err(|e| de::Error::custom(e.to_string()))?;
        let denom = Uint::from_str_radix(denom.trim(), 10)
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
        deserializer.deserialize_string(VPVisitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test that adding fractional voting powers together saturates
    /// on the value of `1/1`.
    #[test]
    fn test_fractional_voting_power_saturates() {
        let mut power = FractionalVotingPower::NULL;
        power += FractionalVotingPower::ONE_THIRD;
        power += FractionalVotingPower::ONE_THIRD;
        power += FractionalVotingPower::ONE_THIRD;
        assert_eq!(power, FractionalVotingPower::WHOLE);
        power += FractionalVotingPower::ONE_THIRD;
        assert_eq!(power, FractionalVotingPower::WHOLE);
    }

    /// This test is ultimately just exercising the underlying
    /// library we use for fractions, we want to make sure
    /// operators work as expected with our FractionalVotingPower
    /// type itself
    #[test]
    fn test_fractional_voting_power_ord_eq() {
        assert!(
            FractionalVotingPower::TWO_THIRDS
                > FractionalVotingPower::new_u64(1, 4).unwrap()
        );
        assert!(
            FractionalVotingPower::ONE_THIRD
                > FractionalVotingPower::new_u64(1, 4).unwrap()
        );
        assert!(
            FractionalVotingPower::ONE_THIRD
                == FractionalVotingPower::new_u64(2, 6).unwrap()
        );
    }

    /// Test error handling on the FractionalVotingPower type
    #[test]
    fn test_fractional_voting_power_valid_fractions() {
        assert!(FractionalVotingPower::new_u64(0, 0).is_err());
        assert!(FractionalVotingPower::new_u64(1, 0).is_err());
        assert!(FractionalVotingPower::new_u64(0, 1).is_ok());
        assert!(FractionalVotingPower::new_u64(1, 1).is_ok());
        assert!(FractionalVotingPower::new_u64(1, 2).is_ok());
        assert!(FractionalVotingPower::new_u64(3, 2).is_err());
    }

    /// Test that serde (de)-serializing pretty prints FractionalVotingPowers.
    #[test]
    fn test_serialize_fractional_voting_power() {
        let vp = FractionalVotingPower::new_u64(1, 2).expect("Test failed");
        let serialized = serde_json::to_string(&vp).expect("Test failed");
        assert_eq!(serialized.as_str(), r#""1 / 2""#);
        let deserialized: FractionalVotingPower =
            serde_json::from_str(&serialized).expect("Test failed");
        assert_eq!(deserialized, vp);
    }
}
