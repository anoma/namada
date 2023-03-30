//! A basic fungible token

use std::fmt::Display;
use std::ops::{Add, AddAssign, Mul, Sub, SubAssign};
use std::str::FromStr;

use borsh::{BorshDeserialize, BorshSchema, BorshSerialize};
use masp_primitives::transaction::Transaction;
use rust_decimal::prelude::{Decimal, ToPrimitive};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::types::address::{masp, Address, DecodeError as AddressError};
use crate::types::storage::{DbKeySeg, Key, KeySeg};

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
    micro: u64,
}

/// Maximum decimal places in a token [`Amount`] and [`Change`].
pub const MAX_DECIMAL_PLACES: u32 = 6;
/// Decimal scale of token [`Amount`] and [`Change`].
pub const SCALE: u64 = 1_000_000;

/// The largest value that can be represented by this integer type
pub const MAX_AMOUNT: Amount = Amount { micro: u64::MAX };

/// A change in tokens amount
pub type Change = i128;

impl Amount {
    /// Get the amount as a [`Change`]
    pub fn change(&self) -> Change {
        self.micro as Change
    }

    /// Spend a given amount.
    /// Panics when given `amount` > `self.micro` amount.
    pub fn spend(&mut self, amount: &Amount) {
        self.micro = self.micro.checked_sub(amount.micro).unwrap();
    }

    /// Receive a given amount.
    /// Panics on overflow.
    pub fn receive(&mut self, amount: &Amount) {
        self.micro = self.micro.checked_add(amount.micro).unwrap();
    }

    /// Create a new amount from whole number of tokens
    pub const fn whole(amount: u64) -> Self {
        Self {
            micro: amount * SCALE,
        }
    }

    /// Create a new amount with the maximum value
    pub fn max() -> Self {
        Self { micro: u64::MAX }
    }

    /// Checked addition. Returns `None` on overflow.
    pub fn checked_add(&self, amount: Amount) -> Option<Self> {
        self.micro
            .checked_add(amount.micro)
            .map(|result| Self { micro: result })
    }

    /// Checked subtraction. Returns `None` on underflow
    pub fn checked_sub(&self, amount: Amount) -> Option<Self> {
        self.micro
            .checked_sub(amount.micro)
            .map(|result| Self { micro: result })
    }

    /// Create amount from Change
    ///
    /// # Panics
    ///
    /// Panics if the change is negative or overflows `u64`.
    pub fn from_change(change: Change) -> Self {
        Self {
            micro: change as u64,
        }
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
        let amount_string = self.to_string();
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
        Self::from_str(&amount_string).map_err(D::Error::custom)
    }
}

impl From<Amount> for Decimal {
    fn from(amount: Amount) -> Self {
        Into::<Decimal>::into(amount.micro) / Into::<Decimal>::into(SCALE)
    }
}

impl From<Decimal> for Amount {
    fn from(micro: Decimal) -> Self {
        let res = (micro * Into::<Decimal>::into(SCALE)).to_u64().unwrap();
        Self { micro: res }
    }
}

impl From<u64> for Amount {
    fn from(micro: u64) -> Self {
        Self { micro }
    }
}

impl From<Amount> for u64 {
    fn from(amount: Amount) -> Self {
        amount.micro
    }
}

impl From<Amount> for u128 {
    fn from(amount: Amount) -> Self {
        u128::from(amount.micro)
    }
}

impl Add for Amount {
    type Output = Amount;

    fn add(mut self, rhs: Self) -> Self::Output {
        self.micro += rhs.micro;
        self
    }
}

impl Mul<u64> for Amount {
    type Output = Amount;

    fn mul(mut self, rhs: u64) -> Self::Output {
        self.micro *= rhs;
        self
    }
}

/// A combination of Euclidean division and fractions:
/// x*(a,b) = (a*(x//b), x%b)
impl Mul<(u64, u64)> for Amount {
    type Output = (Amount, Amount);

    fn mul(mut self, rhs: (u64, u64)) -> Self::Output {
        let ant = Amount::from((self.micro / rhs.1) * rhs.0);
        self.micro %= rhs.1;
        (ant, self)
    }
}

impl Mul<Amount> for u64 {
    type Output = Amount;

    fn mul(mut self, rhs: Amount) -> Self::Output {
        self *= rhs.micro;
        Self::Output::from(self)
    }
}

impl AddAssign for Amount {
    fn add_assign(&mut self, rhs: Self) {
        self.micro += rhs.micro
    }
}

impl Sub for Amount {
    type Output = Amount;

    fn sub(mut self, rhs: Self) -> Self::Output {
        self.micro -= rhs.micro;
        self
    }
}

impl SubAssign for Amount {
    fn sub_assign(&mut self, rhs: Self) {
        self.micro -= rhs.micro
    }
}

impl KeySeg for Amount {
    fn parse(string: String) -> super::storage::Result<Self>
    where
        Self: Sized,
    {
        let micro = u64::parse(string)?;
        Ok(Self { micro })
    }

    fn raw(&self) -> String {
        self.micro.raw()
    }

    fn to_db_key(&self) -> DbKeySeg {
        self.micro.to_db_key()
    }
}

#[allow(missing_docs)]
#[derive(Error, Debug)]
pub enum AmountParseError {
    #[error("Error decoding token amount: {0}")]
    InvalidDecimal(rust_decimal::Error),
    #[error(
        "Error decoding token amount, too many decimal places: {0}. Maximum \
         {MAX_DECIMAL_PLACES}"
    )]
    ScaleTooLarge(u32),
    #[error("Error decoding token amount, the value is within invalid range.")]
    InvalidRange,
}

impl FromStr for Amount {
    type Err = AmountParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match rust_decimal::Decimal::from_str(s) {
            Ok(decimal) => {
                let scale = decimal.scale();
                if scale > MAX_DECIMAL_PLACES {
                    return Err(AmountParseError::ScaleTooLarge(scale));
                }
                let whole =
                    decimal * rust_decimal::Decimal::new(SCALE as i64, 0);
                let micro: u64 =
                    rust_decimal::prelude::ToPrimitive::to_u64(&whole)
                        .ok_or(AmountParseError::InvalidRange)?;
                Ok(Self { micro })
            }
            Err(err) => Err(AmountParseError::InvalidDecimal(err)),
        }
    }
}

impl Display for Amount {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let decimal = rust_decimal::Decimal::from_i128_with_scale(
            self.micro as i128,
            MAX_DECIMAL_PLACES,
        )
        .normalize();
        write!(f, "{}", decimal)
    }
}

impl From<Amount> for Change {
    fn from(amount: Amount) -> Self {
        amount.micro as i128
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
const TOTAL_SUPPLY_STORAGE_KEY: &str = "total_supply";

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

/// Storage key for total supply of a token
pub fn total_supply_key(token_address: &Address) -> Key {
    Key::from(token_address.to_db_key())
        .push(&TOTAL_SUPPLY_STORAGE_KEY.to_owned())
        .expect("Cannot obtain a storage key")
}

/// Is storage key for total supply of a specific token?
pub fn is_total_supply_key(key: &Key, token_address: &Address) -> bool {
    matches!(&key.segments[..], [DbKeySeg::AddressSeg(addr), DbKeySeg::StringSeg(key)] if addr == token_address && key == TOTAL_SUPPLY_STORAGE_KEY)
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
    pub amount: Amount,
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
            Amount::from_str(&data.amount).map_err(TransferError::Amount)?;
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
        any::<u64>().prop_map(Amount::from)
    }

    /// Generate an arbitrary token amount up to and including given `max` value
    pub fn arb_amount_ceiled(max: u64) -> impl Strategy<Value = Amount> {
        (0..=max).prop_map(Amount::from)
    }

    /// Generate an arbitrary non-zero token amount up to and including given
    /// `max` value
    pub fn arb_amount_non_zero_ceiled(
        max: u64,
    ) -> impl Strategy<Value = Amount> {
        (1..=max).prop_map(Amount::from)
    }
}
