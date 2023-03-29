//! A basic fungible token

//use std::fmt::Display;
use std::ops::{Add, AddAssign, Mul, Sub, SubAssign};
use std::str::FromStr;

use borsh::{BorshDeserialize, BorshSchema, BorshSerialize};
use masp_primitives::transaction::Transaction;
use rust_decimal::prelude::Decimal;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::types::address::{masp, Address, DecodeError as AddressError};
use crate::types::storage::{DbKeySeg, Key, KeySeg};
use crate::types::uint::{self, SignedUint, Uint};

/// Amount in micro units. For different granularity another representation
/// might be more appropriate.
#[derive(
    Clone,
    Copy,
    Default,
    BorshSerialize,
    BorshDeserialize,
    BorshSchema,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Debug,
    Hash,
)]
pub struct Amount {
    raw: Uint,
}

/// A number of decimal places for a token [`Amount`].
pub type Denom = u8;

/// Maximum decimal places in a native token [`Amount`] and [`Change`].
/// For non-native (e.g. ERC20 tokens) one must read the `denom_key` storage
/// key.
pub const NATIVE_MAX_DECIMAL_PLACES: u8 = 6;

/// Decimal scale of a native token [`Amount`] and [`Change`].
/// For non-native (e.g. ERC20 tokens) one must read the `denom_key` storage
/// key.
pub const NATIVE_SCALE: u64 = 1_000_000;

/// A change in tokens amount
pub type Change = SignedUint;

impl Amount {
    /// Get the amount as a [`Change`]
    pub fn change(&self) -> Change {
        self.raw.try_into().unwrap()
    }

    /// Spend a given amount.
    /// Panics when given `amount` > `self.raw` amount.
    pub fn spend(&mut self, amount: &Amount) {
        self.raw = self.raw.checked_sub(amount.raw).unwrap();
    }

    /// Receive a given amount.
    /// Panics on overflow and when [`uint::MAX_VALUE`] is exceeded.
    pub fn receive(&mut self, amount: &Amount) {
        self.raw = self.raw.checked_add(amount.raw).unwrap();
    }

    /// Create a new amount of native token from whole number of tokens
    pub fn native_whole(amount: u64) -> Self {
        Self {
            raw: Uint::from(amount) * NATIVE_SCALE,
        }
    }

    /// Create a new amount with the maximum value
    pub fn max() -> Self {
        Self {
            raw: uint::MAX_VALUE,
        }
    }

    /// Checked addition. Returns `None` on overflow or if
    /// the amount exceed [`uint::MAX_VALUE`]
    pub fn checked_add(&self, amount: Amount) -> Option<Self> {
        self.raw.checked_add(amount.raw).and_then(|result| {
            if result < uint::MAX_VALUE {
                Some(Self { raw: result })
            } else {
                None
            }
        })
    }

    /// Checked subtraction. Returns `None` on underflow
    pub fn checked_sub(&self, amount: Amount) -> Option<Self> {
        self.raw
            .checked_sub(amount.raw)
            .map(|result| Self { raw: result })
    }

    /// Create amount from the absolute value of `Change`.
    pub fn from_change(change: Change) -> Self {
        Self { raw: change.abs() }
    }

    /// Attempt to convert a `Decimal` to an `DenominatedAmount` with the
    /// specified precision.
    pub fn from_decimal(
        decimal: Decimal,
        denom: impl Into<u8>,
    ) -> Result<Self, AmountParseError> {
        let denom = denom.into();
        if (denom as u32) < decimal.scale() {
            Err(AmountParseError::ScaleTooLarge(decimal.scale(), denom))
        } else {
            let value = Uint::from(decimal.mantissa().unsigned_abs());
            match Uint::from(10)
                .checked_pow(Uint::from((denom as u32) - decimal.scale()))
                .and_then(|scaling| scaling.checked_mul(value))
            {
                Some(amount) => Ok(Self { raw: amount }),
                None => Err(AmountParseError::ConvertToDecimal),
            }
        }
    }

    /// Given a string and a denomination, parse an amount from string.
    pub fn from_str(
        string: impl AsRef<str>,
        denom: impl Into<u8>,
    ) -> Result<Amount, AmountParseError> {
        match Decimal::from_str(string.as_ref()) {
            Ok(dec) => Ok(Self::from_decimal(dec, denom)?),
            Err(err) => Err(AmountParseError::InvalidDecimal(err)),
        }
    }

    /// Attempt to convert a float to an `Amount` with the specified
    /// precision.
    pub fn from_float(
        float: impl Into<f64>,
        denom: impl Into<u8>,
    ) -> Result<Self, AmountParseError> {
        match Decimal::try_from(float.into()) {
            Err(e) => Err(AmountParseError::InvalidDecimal(e)),
            Ok(decimal) => Self::from_decimal(decimal, denom),
        }
    }

    /// Attempt to convert an unsigned interger to an `Amount` with the
    /// specified precision.
    pub fn from_int(
        uint: impl Into<u64>,
        denom: impl Into<u8>,
    ) -> Result<Self, AmountParseError> {
        Self::from_decimal(Decimal::try_from(uint.into()).unwrap(), denom)
    }
}

/// The number of decimal places in base 10 of an amount.
#[derive(
    Debug,
    Copy,
    Clone,
    Hash,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    BorshSerialize,
    BorshDeserialize,
    BorshSchema,
)]
pub struct Denomination(pub u8);

impl From<u8> for Denomination {
    fn from(denom: u8) -> Self {
        Self(denom)
    }
}

impl From<Denomination> for u8 {
    fn from(denom: Denomination) -> Self {
        denom.0
    }
}

/// An amount with its denomination.
#[derive(
    Debug,
    Copy,
    Clone,
    Hash,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    BorshSerialize,
    BorshDeserialize,
    BorshSchema,
)]
pub struct DenominatedAmount {
    /// The mantissa
    pub amount: Amount,
    /// The number of decimal places in base ten.
    pub denom: Denomination,
}

impl DenominatedAmount {
    /// A precise string representation. The number of
    /// decimal places in this string gives the denomination.
    /// This not true of the string produced by the `Display`
    /// trait.
    pub fn to_string_precise(&self) -> String {
        let decimals = self.denom.0 as usize;
        let mut string = self.amount.raw.to_string();
        if string.len() > decimals {
            string.insert(string.len() - decimals, '.');
        } else {
            for _ in string.len()..decimals {
                string.insert(0, '0');
            }
            string.insert(0, '.');
            string.insert(0, '0');
        }
        string
    }
}

impl FromStr for DenominatedAmount {
    type Err = AmountParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let decimal = Decimal::from_str(s)
            .map_err(AmountParseError::InvalidDecimal)?;
        let denom = Denomination(decimal.scale() as u8);
        Ok(Self {
            amount: Amount::from_decimal(decimal, denom)?,
            denom,
        })
    }
}

impl serde::Serialize for Amount {
    fn serialize<S>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let amount_string = self.raw.to_string();
        serde::Serialize::serialize(&amount_string, serializer)
    }
}

impl<'de> serde::Deserialize<'de> for Amount {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error;
        let amount_string: String =
            serde::Deserialize::deserialize(deserializer)?;
        Ok(Self{raw: Uint::from_str(&amount_string).map_err(D::Error::custom)?})
    }
}

impl serde::Serialize for DenominatedAmount {
    fn serialize<S>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let amount_string = self.to_string_precise();
        serde::Serialize::serialize(&amount_string, serializer)
    }
}

impl<'de> serde::Deserialize<'de> for DenominatedAmount {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error;
        let amount_string: String =
            serde::Deserialize::deserialize(deserializer)?;
        Self::from_str(&amount_string).map_err(D::Error::custom)
    }
}

impl TryFrom<Amount> for Decimal {
    type Error = AmountParseError;

    fn try_from(amount: Amount) -> Result<Self, AmountParseError> {
        if amount.raw > Uint([u64::MAX, u64::MAX, 0, 0]) {
            Err(AmountParseError::ConvertToDecimal)
        } else {
            Ok(Into::<Decimal>::into(amount.raw.as_u128())
                / Into::<Decimal>::into(NATIVE_SCALE))
        }
    }
}

impl From<Amount> for u128 {
    fn from(amount: Amount) -> Self {
        amount.raw.as_u128()
    }
}

impl Add for Amount {
    type Output = Amount;

    fn add(mut self, rhs: Self) -> Self::Output {
        self.raw += rhs.raw;
        self
    }
}

impl Mul<u64> for Amount {
    type Output = Amount;

    fn mul(mut self, rhs: u64) -> Self::Output {
        self.raw *= rhs;
        self
    }
}

/// A combination of Euclidean division and fractions:
/// x*(a,b) = (a*(x//b), x%b).
impl Mul<(u64, u64)> for Amount {
    type Output = (Amount, Amount);

    fn mul(mut self, rhs: (u64, u64)) -> Self::Output {
        let amt = Amount {
            raw: (self.raw / rhs.1) * rhs.0,
        };
        self.raw %= rhs.1;
        (amt, self)
    }
}

impl AddAssign for Amount {
    fn add_assign(&mut self, rhs: Self) {
        self.raw += rhs.raw
    }
}

impl Sub for Amount {
    type Output = Amount;

    fn sub(mut self, rhs: Self) -> Self::Output {
        self.raw -= rhs.raw;
        self
    }
}

impl SubAssign for Amount {
    fn sub_assign(&mut self, rhs: Self) {
        self.raw -= rhs.raw
    }
}

impl KeySeg for Amount {
    fn parse(string: String) -> super::storage::Result<Self>
    where
        Self: Sized,
    {
        let raw = Uint::from_str(&string)
            .map_err(|e| super::storage::Error::InvalidKeySeg(e.to_string()))?;
        Ok(Self { raw })
    }

    fn raw(&self) -> String {
        self.raw.to_string()
    }

    fn to_db_key(&self) -> DbKeySeg {
        DbKeySeg::StringSeg(self.raw())
    }
}

#[allow(missing_docs)]
#[derive(Error, Debug)]
pub enum AmountParseError {
    #[error("Error decoding token amount: {0}")]
    InvalidDecimal(rust_decimal::Error),
    #[error(
        "Error decoding token amount, too many decimal places: {0}. Maximum \
         {1}"
    )]
    ScaleTooLarge(u32, u8),
    #[error(
        "Error decoding token amount, the value is not within invalid range."
    )]
    InvalidRange,
    #[error("Error converting amount to decimal, number too large.")]
    ConvertToDecimal,
}

// impl Display for DenominatedAmount {
// fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
// let string = self.to_string_precise();
// let string = string.trim_end_matches(&['0', '.']);
// f.write_str(string)
// }
// }

impl From<Amount> for Change {
    fn from(amount: Amount) -> Self {
        amount.raw.try_into().unwrap()
    }
}

impl From<DenominatedAmount> for Amount {
    fn from(amt: DenominatedAmount) -> Self {
        amt.amount
    }
}

/// Key segment for a balance key
pub const BALANCE_STORAGE_KEY: &str = "balance";
/// Key segment for head shielded transaction pointer key
pub const HEAD_TX_KEY: &str = "head-tx";
/// Key segment prefix for shielded transaction key
pub const TX_KEY_PREFIX: &str = "tx-";
/// Key segment prefix for MASP conversions
pub const CONVERSION_KEY_PREFIX: &str = "conv";
/// Key segment prefix for pinned shielded transactions
pub const PIN_KEY_PREFIX: &str = "pin-";

/// Obtain a storage key for user's balance.
pub fn balance_key(token_addr: &Address, owner: &Address) -> Key {
    Key::from(token_addr.to_db_key())
        .push(&BALANCE_STORAGE_KEY.to_owned())
        .expect("Cannot obtain a storage key")
        .push(&owner.to_db_key())
        .expect("Cannot obtain a storage key")
}

/// Obtain a storage key prefix for all users' balances.
pub fn balance_prefix(token_addr: &Address) -> Key {
    Key::from(token_addr.to_db_key())
        .push(&BALANCE_STORAGE_KEY.to_owned())
        .expect("Cannot obtain a storage key")
}

/// Obtain a storage key prefix for multitoken balances.
pub fn multitoken_balance_prefix(
    token_addr: &Address,
    sub_prefix: &Key,
) -> Key {
    Key::from(token_addr.to_db_key()).join(sub_prefix)
}

/// Obtain a storage key for user's multitoken balance.
pub fn multitoken_balance_key(prefix: &Key, owner: &Address) -> Key {
    prefix
        .push(&BALANCE_STORAGE_KEY.to_owned())
        .expect("Cannot obtain a storage key")
        .push(&owner.to_db_key())
        .expect("Cannot obtain a storage key")
}

/// Check if the given storage key is balance key for the given token. If it is,
/// returns the owner.
pub fn is_balance_key<'a>(
    token_addr: &Address,
    key: &'a Key,
) -> Option<&'a Address> {
    match &key.segments[..] {
        [
            DbKeySeg::AddressSeg(addr),
            DbKeySeg::StringSeg(key),
            DbKeySeg::AddressSeg(owner),
        ] if key == BALANCE_STORAGE_KEY && addr == token_addr => Some(owner),
        _ => None,
    }
}

/// Check if the given storage key is balance key for unspecified token. If it
/// is, returns the owner.
pub fn is_any_token_balance_key(key: &Key) -> Option<&Address> {
    match &key.segments[..] {
        [
            DbKeySeg::AddressSeg(_),
            DbKeySeg::StringSeg(key),
            DbKeySeg::AddressSeg(owner),
        ] if key == BALANCE_STORAGE_KEY => Some(owner),
        _ => None,
    }
}

/// Check if the given storage key is a masp key
pub fn is_masp_key(key: &Key) -> bool {
    matches!(&key.segments[..],
        [DbKeySeg::AddressSeg(addr), DbKeySeg::StringSeg(key)]
            if *addr == masp()
                && (key == HEAD_TX_KEY
                    || key.starts_with(TX_KEY_PREFIX)
                    || key.starts_with(PIN_KEY_PREFIX)))
}

/// Check if the given storage key is multitoken balance key for the given
/// token. If it is, returns the sub prefix and the owner.
pub fn is_multitoken_balance_key<'a>(
    token_addr: &Address,
    key: &'a Key,
) -> Option<(Key, &'a Address)> {
    match key.segments.first() {
        Some(DbKeySeg::AddressSeg(addr)) if addr == token_addr => {
            multitoken_balance_owner(key)
        }
        _ => None,
    }
}

/// Check if the given storage key is multitoken balance key for unspecified
/// token. If it is, returns the sub prefix and the owner.
pub fn is_any_multitoken_balance_key(key: &Key) -> Option<(Key, &Address)> {
    match key.segments.first() {
        Some(DbKeySeg::AddressSeg(_)) => multitoken_balance_owner(key),
        _ => None,
    }
}

fn multitoken_balance_owner(key: &Key) -> Option<(Key, &Address)> {
    let len = key.segments.len();
    if len < 4 {
        // the key of a multitoken should have 1 or more segments other than
        // token, balance, owner
        return None;
    }
    match &key.segments[..] {
        [
            ..,
            DbKeySeg::StringSeg(balance),
            DbKeySeg::AddressSeg(owner),
        ] if balance == BALANCE_STORAGE_KEY => {
            let sub_prefix = Key {
                segments: key.segments[1..(len - 2)].to_vec(),
            };
            Some((sub_prefix, owner))
        }
        _ => None,
    }
}

/// A simple bilateral token transfer
#[derive(
    Debug,
    Clone,
    PartialEq,
    BorshSerialize,
    BorshDeserialize,
    BorshSchema,
    Hash,
    Eq,
    PartialOrd,
    Serialize,
    Deserialize,
)]
pub struct Transfer {
    /// Source address will spend the tokens
    pub source: Address,
    /// Target address will receive the tokens
    pub target: Address,
    /// Token's address
    pub token: Address,
    /// Source token's sub prefix
    pub sub_prefix: Option<Key>,
    /// The amount of tokens
    pub amount: DenominatedAmount,
    /// The unused storage location at which to place TxId
    pub key: Option<String>,
    /// Shielded transaction part
    pub shielded: Option<Transaction>,
}

#[allow(missing_docs)]
#[derive(Error, Debug)]
pub enum TransferError {
    #[error("Invalid address is specified: {0}")]
    Address(AddressError),
    #[error("Invalid amount: {0}")]
    Amount(AmountParseError),
    #[error("No token is specified")]
    NoToken,
}

#[cfg(any(feature = "abciplus", feature = "abcipp"))]
impl TryFrom<crate::ledger::ibc::data::FungibleTokenPacketData> for Transfer {
    type Error = TransferError;

    fn try_from(
        data: crate::ledger::ibc::data::FungibleTokenPacketData,
    ) -> Result<Self, Self::Error> {
        let source =
            Address::decode(&data.sender).map_err(TransferError::Address)?;
        let target =
            Address::decode(&data.receiver).map_err(TransferError::Address)?;
        let token_str =
            data.denom.split('/').last().ok_or(TransferError::NoToken)?;
        let token =
            Address::decode(token_str).map_err(TransferError::Address)?;
        let amount =
            DenominatedAmount::from_str(&data.amount).map_err(TransferError::Amount)?;
        Ok(Self {
            source,
            target,
            token,
            sub_prefix: None,
            amount,
            key: None,
            shielded: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    proptest! {
            /// The upper limit is set to `2^51`, because then the float is
            /// starting to lose precision.
            #[test]
            fn test_token_amount_decimal_conversion(raw_amount in 0..2_u64.pow(51)) {
                let amount = Amount::from(raw_amount);
                // A round-trip conversion to and from Decimal should be an identity
                let decimal = Decimal::from(amount);
                let identity = Amount::from(decimal);
                assert_eq!(amount, identity);
        }
    }

    #[test]
    fn test_token_display() {
        let max = Amount::from(u64::MAX);
        assert_eq!("18446744073709.551615", max.to_string());

        let whole = Amount::from(u64::MAX / SCALE * SCALE);
        assert_eq!("18446744073709", whole.to_string());

        let trailing_zeroes = Amount::from(123000);
        assert_eq!("0.123", trailing_zeroes.to_string());

        let zero = Amount::from(0);
        assert_eq!("0", zero.to_string());
    }

    #[test]
    fn test_amount_checked_sub() {
        let max = Amount::from(u64::MAX);
        let one = Amount::from(1);
        let zero = Amount::from(0);

        assert_eq!(zero.checked_sub(zero), Some(zero));
        assert_eq!(zero.checked_sub(one), None);
        assert_eq!(zero.checked_sub(max), None);

        assert_eq!(max.checked_sub(zero), Some(max));
        assert_eq!(max.checked_sub(one), Some(max - one));
        assert_eq!(max.checked_sub(max), Some(zero));
    }

    #[test]
    fn test_amount_checked_add() {
        let max = Amount::from(u64::MAX);
        let one = Amount::from(1);
        let zero = Amount::from(0);

        assert_eq!(zero.checked_add(zero), Some(zero));
        assert_eq!(zero.checked_add(one), Some(one));
        assert_eq!(zero.checked_add(max - one), Some(max - one));
        assert_eq!(zero.checked_add(max), Some(max));

        assert_eq!(max.checked_add(zero), Some(max));
        assert_eq!(max.checked_add(one), None);
        assert_eq!(max.checked_add(max), None);
    }
}

/// Helpers for testing with addresses.
#[cfg(any(test, feature = "testing"))]
pub mod testing {
    use proptest::prelude::*;

    use super::*;

    /// Generate an arbitrary token amount
    pub fn arb_amount() -> impl Strategy<Value = Amount> {
        any::<u64>().prop_map(Amount::native_whole)
    }

    /// Generate an arbitrary token amount up to and including given `max` value
    pub fn arb_amount_ceiled(max: u64) -> impl Strategy<Value = Amount> {
        (0..=max).prop_map(Amount::native_whole)
    }

    /// Generate an arbitrary non-zero token amount up to and including given
    /// `max` value
    pub fn arb_amount_non_zero_ceiled(
        max: u64,
    ) -> impl Strategy<Value = Amount> {
        (1..=max).prop_map(Amount::native_whole)
    }
}
